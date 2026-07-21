// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT

use openmls_traits::types::{
    CryptoError, ExporterSecret, HpkeCiphertext, HpkeConfig, HpkeKeyPair, KemOutput,
};
#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
use openmls_traits::types::{HpkeAeadType, HpkeKdfType, HpkeKemType};
use reallyme_crypto::hpke::{
    self as reallyme_hpke, HpkeOpenRequest, HpkeReceiverExportRequest, HpkeSealRequest,
    HpkeSenderExportRequest, HpkeSuite,
};
#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
use reallyme_crypto::hpke::{
    HPKE_MLKEM1024P384_SHAKE256_AES256GCM, HPKE_MLKEM1024_SHAKE256_AES256GCM,
    HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
};
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason, ProviderErrorReason};
use zeroize::Zeroizing;

#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
use reallyme_crypto::x_wing::{generate_x_wing_768_keypair_derand, X_WING_SECRET_KEY_LEN};
#[cfg(feature = "targeted-messages-draft")]
use reallyme_crypto::x_wing::{
    x_wing_768_decapsulate, x_wing_768_encapsulate, X_WING_768_CIPHERTEXT_LEN,
    X_WING_768_PUBLIC_KEY_LEN,
};
#[cfg(feature = "targeted-messages-draft")]
use secrecy::{ExposeSecret, SecretBox};

#[cfg(feature = "targeted-messages-draft")]
use crate::{
    crypto::{chacha_decrypt, chacha_encrypt},
    kdf::{checked_concat, hkdf_expand_sha256, hkdf_extract_sha256},
};

#[cfg(feature = "targeted-messages-draft")]
const HPKE_VERSION: &[u8] = b"HPKE-v1";
#[cfg(feature = "targeted-messages-draft")]
const HPKE_MINIMUM_PSK_LENGTH: usize = 32;
#[cfg(feature = "targeted-messages-draft")]
const HPKE_KEY_LENGTH: usize = 32;
#[cfg(feature = "targeted-messages-draft")]
const HPKE_NONCE_LENGTH: usize = 12;

#[cfg(feature = "targeted-messages-draft")]
// OpenMLS names the deployed X-Wing MLS ciphersuite with 0x004d, but HPKE uses
// the X-Wing draft-06 KEM codepoint 0x647a. This preserves wire compatibility
// with the existing libcrux provider and ReallyMe HPKE's X-Wing suite.
const HPKE_SUITE_ID: [u8; 10] = [b'H', b'P', b'K', b'E', 0x64, 0x7a, 0x00, 0x01, 0x00, 0x03];

#[cfg(feature = "targeted-messages-draft")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HpkeErrorReason {
    InvalidPsk,
    InvalidLength,
    KdfFailure,
    AeadFailure,
}

#[cfg(feature = "targeted-messages-draft")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HpkeMode {
    Psk,
}

#[cfg(feature = "targeted-messages-draft")]
impl HpkeMode {
    const fn code(self) -> u8 {
        match self {
            Self::Psk => 0x01,
        }
    }
}

#[cfg(feature = "targeted-messages-draft")]
pub(crate) struct HpkeContext {
    key: SecretBox<[u8; HPKE_KEY_LENGTH]>,
    base_nonce: SecretBox<[u8; HPKE_NONCE_LENGTH]>,
}

#[cfg(feature = "targeted-messages-draft")]
impl HpkeContext {
    fn new(
        mode: HpkeMode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, HpkeErrorReason> {
        validate_psk(psk, psk_id)?;

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
        Ok(Self {
            key: fixed_secret::<HPKE_KEY_LENGTH>(&key)?,
            base_nonce: fixed_secret::<HPKE_NONCE_LENGTH>(&base_nonce)?,
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
}

#[cfg(feature = "targeted-messages-draft")]
fn fixed_secret<const N: usize>(input: &[u8]) -> Result<SecretBox<[u8; N]>, HpkeErrorReason> {
    let value = <[u8; N]>::try_from(input).map_err(|_| HpkeErrorReason::InvalidLength)?;
    Ok(SecretBox::new(Box::new(value)))
}

#[cfg(feature = "targeted-messages-draft")]
fn validate_psk(psk: &[u8], psk_id: &[u8]) -> Result<(), HpkeErrorReason> {
    if psk.len() < HPKE_MINIMUM_PSK_LENGTH || psk_id.is_empty() {
        return Err(HpkeErrorReason::InvalidPsk);
    }
    Ok(())
}

#[cfg(feature = "targeted-messages-draft")]
fn labeled_extract(
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Result<Zeroizing<Vec<u8>>, HpkeErrorReason> {
    let labeled_ikm = checked_concat(&[HPKE_VERSION, &HPKE_SUITE_ID, label, ikm])
        .map_err(|_| HpkeErrorReason::InvalidLength)?;
    hkdf_extract_sha256(salt, &labeled_ikm).map_err(|_| HpkeErrorReason::KdfFailure)
}

#[cfg(feature = "targeted-messages-draft")]
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

fn reallyme_suite(config: &HpkeConfig) -> Result<HpkeSuite, CryptoError> {
    match (config.0, config.1, config.2) {
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        (HpkeKemType::XWingKemDraft6, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
            Ok(HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305)
        }
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        (HpkeKemType::MlKem1024, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
            Ok(HPKE_MLKEM1024_SHAKE256_AES256GCM)
        }
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        (HpkeKemType::MlKem1024P384, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
            Ok(HPKE_MLKEM1024P384_SHAKE256_AES256GCM)
        }
        _ => Err(CryptoError::UnsupportedCiphersuite),
    }
}

pub(crate) fn seal(
    config: HpkeConfig,
    public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeCiphertext, CryptoError> {
    let suite = reallyme_suite(&config)?;
    let output = reallyme_hpke::seal_base(&HpkeSealRequest {
        suite,
        recipient_public_key: public_key,
        info,
        aad,
        plaintext,
    })
    .map_err(map_seal_error)?;
    Ok(HpkeCiphertext {
        kem_output: output.encapsulated_key.into(),
        ciphertext: output.ciphertext.into(),
    })
}

pub(crate) fn open(
    config: HpkeConfig,
    input: &HpkeCiphertext,
    secret_key: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let suite = reallyme_suite(&config)?;
    let output = reallyme_hpke::open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: input.kem_output.as_slice(),
        recipient_private_key: secret_key,
        info,
        aad,
        ciphertext: input.ciphertext.as_slice(),
    })
    .map_err(map_open_error)?;
    Ok(output.plaintext.to_vec())
}

pub(crate) fn derive_keypair(config: HpkeConfig, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
    let suite = reallyme_suite(&config)?;
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    if suite == HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305 {
        let mut seed = Zeroizing::new([0u8; X_WING_SECRET_KEY_LEN]);
        reallyme_crypto_sha3::shake256_expand(ikm, &mut *seed);
        let (public, private) = generate_x_wing_768_keypair_derand(&*seed)
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        return Ok(HpkeKeyPair {
            private: private.as_slice().into(),
            public,
        });
    }
    let input_length = suite
        .private_key_len()
        .map_err(|_| CryptoError::UnsupportedCiphersuite)?;
    let mut input_key_material = Zeroizing::new(vec![0u8; input_length]);
    reallyme_crypto_sha3::shake256_expand(ikm, input_key_material.as_mut_slice());
    let keypair = reallyme_hpke::derive_keypair(suite, input_key_material.as_slice())
        .map_err(map_keygen_error)?;
    Ok(HpkeKeyPair {
        private: keypair.private_key().into(),
        public: keypair.public_key,
    })
}

pub(crate) fn sender_export(
    config: HpkeConfig,
    public_key: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    output_length: usize,
) -> Result<(KemOutput, ExporterSecret), CryptoError> {
    validate_export_length(output_length)?;
    let suite = reallyme_suite(&config)?;
    let output = reallyme_hpke::sender_export(&HpkeSenderExportRequest {
        suite,
        recipient_public_key: public_key,
        info,
        exporter_context,
        output_length,
    })
    .map_err(map_sender_export_error)?;
    let exporter_secret = output.exporter_secret().to_vec();
    Ok((output.encapsulated_key, exporter_secret.into()))
}

pub(crate) fn receiver_export(
    config: HpkeConfig,
    encapsulated: &[u8],
    secret_key: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    output_length: usize,
) -> Result<ExporterSecret, CryptoError> {
    validate_export_length(output_length)?;
    let suite = reallyme_suite(&config)?;
    let output = reallyme_hpke::receiver_export(&HpkeReceiverExportRequest {
        suite,
        encapsulated_key: encapsulated,
        recipient_private_key: secret_key,
        info,
        exporter_context,
        output_length,
    })
    .map_err(map_receiver_export_error)?;
    Ok(output.as_slice().to_vec().into())
}

fn validate_export_length(output_length: usize) -> Result<(), CryptoError> {
    if output_length == 0 || output_length > usize::from(u16::MAX) {
        return Err(CryptoError::ExporterError);
    }
    Ok(())
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
    let context = setup_receiver_psk(
        config,
        input.kem_output.as_slice(),
        secret_key,
        info,
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
    ensure_xwing_psk_config(&config)?;
    if public_key.len() != X_WING_768_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidPublicKey);
    }
    let (encapsulated, shared_secret) =
        x_wing_768_encapsulate(public_key).map_err(|_| CryptoError::SenderSetupError)?;
    let context = HpkeContext::new(HpkeMode::Psk, &shared_secret, info, psk, psk_id)
        .map_err(|_| CryptoError::SenderSetupError)?;
    Ok((encapsulated, context))
}

#[cfg(feature = "targeted-messages-draft")]
fn setup_receiver_psk(
    config: HpkeConfig,
    encapsulated: &[u8],
    secret_key: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<HpkeContext, CryptoError> {
    ensure_xwing_psk_config(&config)?;
    if encapsulated.len() != X_WING_768_CIPHERTEXT_LEN || secret_key.len() != X_WING_SECRET_KEY_LEN
    {
        return Err(CryptoError::InvalidLength);
    }
    let shared_secret = x_wing_768_decapsulate(encapsulated, secret_key)
        .map_err(|_| CryptoError::ReceiverSetupError)?;
    HpkeContext::new(HpkeMode::Psk, &shared_secret, info, psk, psk_id)
        .map_err(|_| CryptoError::ReceiverSetupError)
}

#[cfg(feature = "targeted-messages-draft")]
fn ensure_xwing_psk_config(config: &HpkeConfig) -> Result<(), CryptoError> {
    match (config.0, config.1, config.2) {
        (HpkeKemType::XWingKemDraft6, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
            Ok(())
        }
        _ => Err(CryptoError::UnsupportedCiphersuite),
    }
}

fn map_seal_error(error: OperationError) -> CryptoError {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidPublicKey,
        } => CryptoError::InvalidPublicKey,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        } => CryptoError::InvalidLength,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::LengthOverflow,
        } => CryptoError::TooMuchData,
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CryptoError::UnsupportedCiphersuite,
        OperationError::Provider {
            reason: ProviderErrorReason::RandomnessUnavailable,
        } => CryptoError::InsufficientRandomness,
        OperationError::Primitive { .. }
        | OperationError::Provider { .. }
        | OperationError::Backend { .. } => CryptoError::HpkeEncryptionError,
        _ => CryptoError::HpkeEncryptionError,
    }
}

fn map_open_error(error: OperationError) -> CryptoError {
    match error {
        OperationError::Primitive {
            reason:
                PrimitiveErrorReason::InvalidPrivateKey
                | PrimitiveErrorReason::InvalidPublicKey
                | PrimitiveErrorReason::MalformedCiphertext
                | PrimitiveErrorReason::InvalidLength,
        } => CryptoError::InvalidLength,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::LengthOverflow,
        } => CryptoError::TooMuchData,
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CryptoError::UnsupportedCiphersuite,
        OperationError::Primitive { .. }
        | OperationError::Provider { .. }
        | OperationError::Backend { .. } => CryptoError::HpkeDecryptionError,
        _ => CryptoError::HpkeDecryptionError,
    }
}

fn map_sender_export_error(error: OperationError) -> CryptoError {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidPublicKey,
        } => CryptoError::InvalidPublicKey,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::LengthOverflow,
        } => CryptoError::TooMuchData,
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CryptoError::UnsupportedCiphersuite,
        OperationError::Provider {
            reason: ProviderErrorReason::RandomnessUnavailable,
        } => CryptoError::InsufficientRandomness,
        OperationError::Primitive { .. }
        | OperationError::Provider { .. }
        | OperationError::Backend { .. } => CryptoError::ExporterError,
        _ => CryptoError::ExporterError,
    }
}

fn map_receiver_export_error(error: OperationError) -> CryptoError {
    match error {
        OperationError::Primitive {
            reason:
                PrimitiveErrorReason::InvalidPrivateKey
                | PrimitiveErrorReason::MalformedCiphertext
                | PrimitiveErrorReason::InvalidLength,
        } => CryptoError::InvalidLength,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::LengthOverflow,
        } => CryptoError::TooMuchData,
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CryptoError::UnsupportedCiphersuite,
        OperationError::Primitive { .. }
        | OperationError::Provider { .. }
        | OperationError::Backend { .. } => CryptoError::ExporterError,
        _ => CryptoError::ExporterError,
    }
}

fn map_keygen_error(error: OperationError) -> CryptoError {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        } => CryptoError::InvalidLength,
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CryptoError::UnsupportedCiphersuite,
        OperationError::Provider {
            reason: ProviderErrorReason::RandomnessUnavailable,
        } => CryptoError::InsufficientRandomness,
        OperationError::Primitive { .. }
        | OperationError::Provider { .. }
        | OperationError::Backend { .. } => CryptoError::CryptoLibraryError,
        _ => CryptoError::CryptoLibraryError,
    }
}
