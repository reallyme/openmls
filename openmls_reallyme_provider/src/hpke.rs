use openmls_traits::types::{
    CryptoError, ExporterSecret, HpkeCiphertext, HpkeConfig, HpkeKeyPair, KemOutput,
};
#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
use openmls_traits::types::{HpkeAeadType, HpkeKdfType, HpkeKemType};
use reallyme_crypto::x_wing::{
    generate_x_wing_768_keypair_derand, x_wing_768_decapsulate, x_wing_768_encapsulate,
    X_WING_768_CIPHERTEXT_LEN, X_WING_768_PUBLIC_KEY_LEN, X_WING_SECRET_KEY_LEN,
};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::{
    crypto::{chacha_decrypt, chacha_encrypt},
    kdf::{checked_concat, hkdf_expand_sha256, hkdf_extract_sha256, SHA256_OUTPUT_LENGTH},
};

const HPKE_VERSION: &[u8] = b"HPKE-v1";
#[cfg(feature = "targeted-messages-draft")]
const HPKE_MINIMUM_PSK_LENGTH: usize = 32;
const HPKE_KEY_LENGTH: usize = 32;
const HPKE_NONCE_LENGTH: usize = 12;

// OpenMLS names the draft MLS ciphersuite with 0x004d, but HPKE uses the
// X-Wing draft-06 KEM codepoint 0x647a. This matches hpke-rs 0.7 and the
// existing libcrux provider, preserving cross-provider wire compatibility.
const HPKE_SUITE_ID: [u8; 10] = [b'H', b'P', b'K', b'E', 0x64, 0x7a, 0x00, 0x01, 0x00, 0x03];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HpkeErrorReason {
    InvalidPsk,
    InvalidLength,
    KdfFailure,
    AeadFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HpkeMode {
    Base,
    #[cfg(feature = "targeted-messages-draft")]
    Psk,
}

impl HpkeMode {
    const fn code(self) -> u8 {
        match self {
            Self::Base => 0x00,
            #[cfg(feature = "targeted-messages-draft")]
            Self::Psk => 0x01,
        }
    }
}

pub(crate) struct HpkeContext {
    key: SecretBox<[u8; HPKE_KEY_LENGTH]>,
    base_nonce: SecretBox<[u8; HPKE_NONCE_LENGTH]>,
    exporter_secret: SecretBox<[u8; SHA256_OUTPUT_LENGTH]>,
}

impl HpkeContext {
    fn new(
        mode: HpkeMode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, HpkeErrorReason> {
        validate_psk(mode, psk, psk_id)?;

        let psk_id_hash = labeled_extract(&[], b"psk_id_hash", psk_id)?;
        let info_hash = labeled_extract(&[], b"info_hash", info)?;
        let mode_code = [mode.code()];
        let key_schedule_context = checked_concat(&[&mode_code, &psk_id_hash, &info_hash])
            .map_err(|_| HpkeErrorReason::InvalidLength)?;
        let secret = labeled_extract(shared_secret, b"secret", psk)?;
        let key = labeled_expand(&secret, b"key", &key_schedule_context, HPKE_KEY_LENGTH)?;
        let base_nonce = labeled_expand(
            &secret,
            b"base_nonce",
            &key_schedule_context,
            HPKE_NONCE_LENGTH,
        )?;
        let exporter_secret =
            labeled_expand(&secret, b"exp", &key_schedule_context, SHA256_OUTPUT_LENGTH)?;

        let key = fixed_secret::<HPKE_KEY_LENGTH>(&key)?;
        let base_nonce = fixed_secret::<HPKE_NONCE_LENGTH>(&base_nonce)?;
        let exporter_secret = fixed_secret::<SHA256_OUTPUT_LENGTH>(&exporter_secret)?;

        Ok(Self {
            key,
            base_nonce,
            exporter_secret,
        })
    }

    pub(crate) fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeErrorReason> {
        chacha_encrypt(
            self.key.expose_secret(),
            plaintext,
            self.base_nonce.expose_secret(),
            aad,
        )
        .map_err(|_| HpkeErrorReason::AeadFailure)
    }

    pub(crate) fn open(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeErrorReason> {
        chacha_decrypt(
            self.key.expose_secret(),
            ciphertext,
            self.base_nonce.expose_secret(),
            aad,
        )
        .map_err(|_| HpkeErrorReason::AeadFailure)
    }

    pub(crate) fn export(
        &self,
        exporter_context: &[u8],
        output_length: usize,
    ) -> Result<Zeroizing<Vec<u8>>, HpkeErrorReason> {
        labeled_expand(
            self.exporter_secret.expose_secret(),
            b"sec",
            exporter_context,
            output_length,
        )
    }
}

fn fixed_secret<const N: usize>(input: &[u8]) -> Result<SecretBox<[u8; N]>, HpkeErrorReason> {
    let value = <[u8; N]>::try_from(input).map_err(|_| HpkeErrorReason::InvalidLength)?;
    Ok(SecretBox::new(Box::new(value)))
}

fn validate_psk(mode: HpkeMode, psk: &[u8], psk_id: &[u8]) -> Result<(), HpkeErrorReason> {
    let has_psk = !psk.is_empty();
    let has_psk_id = !psk_id.is_empty();
    if has_psk != has_psk_id {
        return Err(HpkeErrorReason::InvalidPsk);
    }
    match mode {
        HpkeMode::Base if has_psk => Err(HpkeErrorReason::InvalidPsk),
        HpkeMode::Base => Ok(()),
        #[cfg(feature = "targeted-messages-draft")]
        HpkeMode::Psk if !has_psk || psk.len() < HPKE_MINIMUM_PSK_LENGTH => {
            Err(HpkeErrorReason::InvalidPsk)
        }
        #[cfg(feature = "targeted-messages-draft")]
        HpkeMode::Psk => Ok(()),
    }
}

fn labeled_extract(
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Result<Zeroizing<Vec<u8>>, HpkeErrorReason> {
    let labeled_ikm = checked_concat(&[HPKE_VERSION, &HPKE_SUITE_ID, label, ikm])
        .map_err(|_| HpkeErrorReason::InvalidLength)?;
    hkdf_extract_sha256(salt, &labeled_ikm).map_err(|_| HpkeErrorReason::KdfFailure)
}

fn labeled_expand(
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, HpkeErrorReason> {
    let length = u16::try_from(output_length).map_err(|_| HpkeErrorReason::InvalidLength)?;
    let length_bytes = length.to_be_bytes();
    let labeled_info = checked_concat(&[&length_bytes, HPKE_VERSION, &HPKE_SUITE_ID, label, info])
        .map_err(|_| HpkeErrorReason::InvalidLength)?;
    hkdf_expand_sha256(prk, &labeled_info, output_length).map_err(|_| HpkeErrorReason::KdfFailure)
}

pub(crate) fn is_supported_config(config: &HpkeConfig) -> bool {
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    {
        matches!(
            (&config.0, &config.1, &config.2),
            (
                HpkeKemType::XWingKemDraft6,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::ChaCha20Poly1305
            )
        )
    }
    #[cfg(not(feature = "draft-ietf-mls-pq-ciphersuites"))]
    {
        let _ = config;
        false
    }
}

fn ensure_supported(config: &HpkeConfig) -> Result<(), CryptoError> {
    if is_supported_config(config) {
        Ok(())
    } else {
        Err(CryptoError::UnsupportedCiphersuite)
    }
}

fn setup_sender(
    config: HpkeConfig,
    public_key: &[u8],
    info: &[u8],
    mode: HpkeMode,
    psk: &[u8],
    psk_id: &[u8],
) -> Result<(KemOutput, HpkeContext), CryptoError> {
    ensure_supported(&config)?;
    if public_key.len() != X_WING_768_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidPublicKey);
    }
    let (encapsulated, shared_secret) =
        x_wing_768_encapsulate(public_key).map_err(|_| CryptoError::SenderSetupError)?;
    let context = HpkeContext::new(mode, &shared_secret, info, psk, psk_id)
        .map_err(|_| CryptoError::SenderSetupError)?;
    Ok((encapsulated, context))
}

fn setup_receiver(
    config: HpkeConfig,
    encapsulated: &[u8],
    secret_key: &[u8],
    info: &[u8],
    mode: HpkeMode,
    psk: &[u8],
    psk_id: &[u8],
) -> Result<HpkeContext, CryptoError> {
    ensure_supported(&config)?;
    if encapsulated.len() != X_WING_768_CIPHERTEXT_LEN || secret_key.len() != X_WING_SECRET_KEY_LEN
    {
        return Err(CryptoError::InvalidLength);
    }
    let shared_secret = x_wing_768_decapsulate(encapsulated, secret_key)
        .map_err(|_| CryptoError::ReceiverSetupError)?;
    HpkeContext::new(mode, &shared_secret, info, psk, psk_id)
        .map_err(|_| CryptoError::ReceiverSetupError)
}

pub(crate) fn seal(
    config: HpkeConfig,
    public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeCiphertext, CryptoError> {
    let (kem_output, context) = setup_sender(config, public_key, info, HpkeMode::Base, &[], &[])?;
    let ciphertext = context
        .seal(aad, plaintext)
        .map_err(|_| CryptoError::HpkeEncryptionError)?;
    Ok(HpkeCiphertext {
        kem_output: kem_output.into(),
        ciphertext: ciphertext.into(),
    })
}

pub(crate) fn open(
    config: HpkeConfig,
    input: &HpkeCiphertext,
    secret_key: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let context = setup_receiver(
        config,
        input.kem_output.as_slice(),
        secret_key,
        info,
        HpkeMode::Base,
        &[],
        &[],
    )?;
    context
        .open(aad, input.ciphertext.as_slice())
        .map_err(|_| CryptoError::HpkeDecryptionError)
}

pub(crate) fn sender_export(
    config: HpkeConfig,
    public_key: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    output_length: usize,
) -> Result<(KemOutput, ExporterSecret), CryptoError> {
    let (kem_output, context) = setup_sender(config, public_key, info, HpkeMode::Base, &[], &[])?;
    let exported = context
        .export(exporter_context, output_length)
        .map_err(|_| CryptoError::ExporterError)?;
    Ok((kem_output, exported.to_vec().into()))
}

pub(crate) fn receiver_export(
    config: HpkeConfig,
    encapsulated: &[u8],
    secret_key: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    output_length: usize,
) -> Result<ExporterSecret, CryptoError> {
    let context = setup_receiver(
        config,
        encapsulated,
        secret_key,
        info,
        HpkeMode::Base,
        &[],
        &[],
    )?;
    context
        .export(exporter_context, output_length)
        .map(|secret| secret.to_vec().into())
        .map_err(|_| CryptoError::ExporterError)
}

pub(crate) fn derive_keypair(config: HpkeConfig, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
    ensure_supported(&config)?;
    let mut seed = Zeroizing::new([0u8; X_WING_SECRET_KEY_LEN]);
    reallyme_crypto_sha3::shake256_expand(ikm, &mut *seed);
    let (public, private) =
        generate_x_wing_768_keypair_derand(&*seed).map_err(|_| CryptoError::CryptoLibraryError)?;
    Ok(HpkeKeyPair {
        private: private.as_slice().into(),
        public,
    })
}

#[cfg(feature = "targeted-messages-draft")]
pub(crate) fn open_psk(
    config: HpkeConfig,
    input: &HpkeCiphertext,
    secret_key: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let context = setup_receiver(
        config,
        input.kem_output.as_slice(),
        secret_key,
        info,
        HpkeMode::Psk,
        psk,
        psk_id,
    )?;
    context
        .open(aad, input.ciphertext.as_slice())
        .map_err(|_| CryptoError::HpkeDecryptionError)
}

#[cfg(feature = "targeted-messages-draft")]
pub(crate) fn setup_sender_psk(
    config: HpkeConfig,
    public_key: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<(KemOutput, HpkeContext), CryptoError> {
    setup_sender(config, public_key, info, HpkeMode::Psk, psk, psk_id)
}
