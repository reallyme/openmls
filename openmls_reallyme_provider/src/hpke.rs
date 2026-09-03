// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT

use openmls_traits::types::{
    CryptoError, ExporterSecret, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKeyPair, KemOutput,
};
#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
use openmls_traits::types::{HpkeAeadType, HpkeKemType};
use reallyme_crypto::hpke::{
    self as reallyme_hpke, HpkeError, HpkeOpenRequest, HpkeReceiverExportRequest, HpkeSealRequest,
    HpkeSenderExportRequest, HpkeSuite,
};
#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
use reallyme_crypto::hpke::{
    HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM, HPKE_MLKEM1024_HKDF_SHA384_AES256GCM,
    HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
};

const HKDF_MAXIMUM_BLOCK_COUNT: usize = 255;
// HPKE-PQ requires at least 32 bytes for hybrid KEM DeriveKeyPair inputs.
// Enforcing the same security floor for every exposed PQ profile prevents a
// direct trait caller from deriving long-lived tree keys from trivial inputs.
const MINIMUM_DERIVE_KEYPAIR_IKM_LENGTH: usize = 32;
const SHA256_OUTPUT_LENGTH: usize = 32;
const SHA384_OUTPUT_LENGTH: usize = 48;
const SHA512_OUTPUT_LENGTH: usize = 64;

#[cfg(feature = "targeted-messages-draft")]
use reallyme_crypto::hpke::{
    HpkePskIdRef, HpkePskReceiverSetupRequest, HpkePskRef, HpkePskSenderSetupRequest,
};
#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
use zeroize::Zeroizing;

#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
use reallyme_crypto::x_wing::{generate_x_wing_768_keypair_derand, X_WING_SECRET_KEY_LEN};

fn reallyme_suite(config: &HpkeConfig) -> Result<HpkeSuite, CryptoError> {
    match (config.0, config.1, config.2) {
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        (HpkeKemType::XWingKemDraft6, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
            Ok(HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305)
        }
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        (HpkeKemType::MlKem1024, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
            Ok(HPKE_MLKEM1024_HKDF_SHA384_AES256GCM)
        }
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        (HpkeKemType::MlKem1024P384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
            Ok(HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM)
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
    let output = reallyme_hpke::seal_base_raw(&HpkeSealRequest {
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
    let mut output = reallyme_hpke::open_base_raw(&HpkeOpenRequest {
        suite,
        encapsulated_key: input.kem_output.as_slice(),
        recipient_private_key: secret_key,
        info,
        aad,
        ciphertext: input.ciphertext.as_slice(),
    })
    .map_err(map_open_error)?;
    // OpenMLS currently returns plaintext as a plain `Vec<u8>`. Transfer the
    // zeroizing backend allocation instead of copying sensitive bytes into a
    // second allocation that would be dropped without being cleared here.
    Ok(core::mem::take(&mut *output.plaintext))
}

pub(crate) fn derive_keypair(config: HpkeConfig, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
    if ikm.len() < MINIMUM_DERIVE_KEYPAIR_IKM_LENGTH {
        return Err(CryptoError::InvalidLength);
    }
    let suite = reallyme_suite(&config)?;
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    if suite == HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305 {
        // This condition is deliberately profile-specific rather than keyed
        // only on the X-Wing KEM. Standards-tracking suites using KEM 0x647A
        // follow HPKE-PQ's labeled derivation and must not inherit this legacy
        // OpenMLS compatibility rule.
        // ReallyMe Crypto 0.3.6 delegates X-Wing DeriveKeyPair to an HPKE
        // implementation using the older labeled-derive construction. The
        // OpenMLS X-Wing suite is draft-06, which specifies raw
        // SHAKE256(ikm, 32). Normalize here until the pinned backend exposes a
        // draft-06 derivation entry point; the libcrux interoperability test
        // prevents this compatibility boundary from drifting silently.
        let mut seed = Zeroizing::new([0u8; X_WING_SECRET_KEY_LEN]);
        reallyme_crypto_sha3::shake256_expand(ikm, &mut *seed);
        let (public, mut private) = generate_x_wing_768_keypair_derand(&*seed)
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        return Ok(HpkeKeyPair {
            private: core::mem::take(&mut *private).into(),
            public,
        });
    }
    let keypair =
        reallyme_hpke::derive_keypair_from_ikm_raw(suite, ikm).map_err(map_keygen_error)?;
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
    validate_export_length(&config, output_length)?;
    let suite = reallyme_suite(&config)?;
    let mut output = reallyme_hpke::sender_export_raw(&HpkeSenderExportRequest {
        suite,
        recipient_public_key: public_key,
        info,
        exporter_context,
        output_length,
    })
    .map_err(map_sender_export_error)?;
    let encapsulated_key = core::mem::take(&mut output.encapsulated_key);
    let mut exporter_secret = output.into_exporter_secret();
    Ok((
        encapsulated_key,
        core::mem::take(&mut *exporter_secret).into(),
    ))
}

pub(crate) fn receiver_export(
    config: HpkeConfig,
    encapsulated: &[u8],
    secret_key: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    output_length: usize,
) -> Result<ExporterSecret, CryptoError> {
    validate_export_length(&config, output_length)?;
    let suite = reallyme_suite(&config)?;
    let output = reallyme_hpke::receiver_export_raw(&HpkeReceiverExportRequest {
        suite,
        encapsulated_key: encapsulated,
        recipient_private_key: secret_key,
        info,
        exporter_context,
        output_length,
    })
    .map_err(map_receiver_export_error)?;
    // `HpkeExporterSecret` intentionally exposes only a borrow. The copy is
    // immediately moved into OpenMLS' zeroizing `SecretVLBytes` wrapper.
    Ok(output.as_slice().to_vec().into())
}

fn validate_export_length(config: &HpkeConfig, output_length: usize) -> Result<(), CryptoError> {
    let maximum = match config.1 {
        HpkeKdfType::HkdfSha256 => SHA256_OUTPUT_LENGTH
            .checked_mul(HKDF_MAXIMUM_BLOCK_COUNT)
            .ok_or(CryptoError::ExporterError)?,
        HpkeKdfType::HkdfSha384 => SHA384_OUTPUT_LENGTH
            .checked_mul(HKDF_MAXIMUM_BLOCK_COUNT)
            .ok_or(CryptoError::ExporterError)?,
        HpkeKdfType::HkdfSha512 => SHA512_OUTPUT_LENGTH
            .checked_mul(HKDF_MAXIMUM_BLOCK_COUNT)
            .ok_or(CryptoError::ExporterError)?,
    };
    if output_length == 0 || output_length > maximum {
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
    let mut context = setup_receiver_psk(
        config,
        input.kem_output.as_slice(),
        secret_key,
        info,
        psk,
        psk_id,
    )?;
    let mut output = context
        .open(aad, input.ciphertext.as_slice())
        .map_err(map_open_psk_error)?;
    Ok(core::mem::take(&mut *output.plaintext))
}

#[cfg(feature = "targeted-messages-draft")]
pub(crate) fn setup_sender_psk(
    config: HpkeConfig,
    public_key: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<(KemOutput, reallyme_hpke::RawHpkePskSenderContext), CryptoError> {
    let suite = reallyme_suite(&config)?;
    let psk = HpkePskRef::new(psk).map_err(|_| CryptoError::SenderSetupError)?;
    let psk_id = HpkePskIdRef::new(psk_id).map_err(|_| CryptoError::SenderSetupError)?;
    let output = reallyme_hpke::setup_sender_psk_raw(&HpkePskSenderSetupRequest {
        suite,
        recipient_public_key: public_key,
        info,
        psk,
        psk_id,
    })
    .map_err(map_sender_setup_error)?;
    Ok((output.encapsulated_key, output.context))
}

#[cfg(feature = "targeted-messages-draft")]
fn setup_receiver_psk(
    config: HpkeConfig,
    encapsulated: &[u8],
    secret_key: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<reallyme_hpke::RawHpkeReceiverContext, CryptoError> {
    let suite = reallyme_suite(&config)?;
    let psk = HpkePskRef::new(psk).map_err(|_| CryptoError::ReceiverSetupError)?;
    let psk_id = HpkePskIdRef::new(psk_id).map_err(|_| CryptoError::ReceiverSetupError)?;
    reallyme_hpke::setup_receiver_psk_raw(&HpkePskReceiverSetupRequest {
        suite,
        encapsulated_key: encapsulated,
        recipient_private_key: secret_key,
        info,
        psk,
        psk_id,
    })
    .map_err(map_receiver_setup_error)
}

fn map_seal_error(error: HpkeError) -> CryptoError {
    match error {
        HpkeError::UnsupportedKem
        | HpkeError::UnsupportedKdf
        | HpkeError::UnsupportedAead
        | HpkeError::UnsupportedSuite => CryptoError::UnsupportedCiphersuite,
        HpkeError::InvalidPublicKey => CryptoError::InvalidPublicKey,
        HpkeError::InvalidInfoLength
        | HpkeError::InvalidInputKeyMaterial
        | HpkeError::InvalidPsk
        | HpkeError::InvalidPskIdentifier
        | HpkeError::InvalidRandomness => CryptoError::InvalidLength,
        HpkeError::LengthOverflow => CryptoError::TooMuchData,
        HpkeError::RandomnessUnavailable => CryptoError::InsufficientRandomness,
        HpkeError::InvalidPrivateKey
        | HpkeError::InvalidEncapsulatedKey
        | HpkeError::InvalidCiphertext
        | HpkeError::InvalidExporterLength
        | HpkeError::SealFailed
        | HpkeError::OpenFailed
        | HpkeError::ExportFailed
        | HpkeError::KeyGenerationFailed => CryptoError::HpkeEncryptionError,
        _ => CryptoError::HpkeEncryptionError,
    }
}

fn map_open_error(error: HpkeError) -> CryptoError {
    match error {
        HpkeError::UnsupportedKem
        | HpkeError::UnsupportedKdf
        | HpkeError::UnsupportedAead
        | HpkeError::UnsupportedSuite => CryptoError::UnsupportedCiphersuite,
        HpkeError::InvalidPublicKey => CryptoError::InvalidPublicKey,
        HpkeError::InvalidPrivateKey
        | HpkeError::InvalidEncapsulatedKey
        | HpkeError::InvalidCiphertext
        | HpkeError::InvalidInfoLength
        | HpkeError::InvalidInputKeyMaterial
        | HpkeError::InvalidPsk
        | HpkeError::InvalidPskIdentifier
        | HpkeError::InvalidRandomness => CryptoError::InvalidLength,
        HpkeError::LengthOverflow => CryptoError::TooMuchData,
        HpkeError::RandomnessUnavailable => CryptoError::InsufficientRandomness,
        HpkeError::OpenFailed
        | HpkeError::SealFailed
        | HpkeError::ExportFailed
        | HpkeError::InvalidExporterLength
        | HpkeError::KeyGenerationFailed => CryptoError::HpkeDecryptionError,
        _ => CryptoError::HpkeDecryptionError,
    }
}

fn map_sender_export_error(error: HpkeError) -> CryptoError {
    match error {
        HpkeError::UnsupportedKem
        | HpkeError::UnsupportedKdf
        | HpkeError::UnsupportedAead
        | HpkeError::UnsupportedSuite => CryptoError::UnsupportedCiphersuite,
        HpkeError::InvalidPublicKey => CryptoError::InvalidPublicKey,
        HpkeError::LengthOverflow => CryptoError::TooMuchData,
        HpkeError::RandomnessUnavailable => CryptoError::InsufficientRandomness,
        HpkeError::InvalidPrivateKey
        | HpkeError::InvalidEncapsulatedKey
        | HpkeError::InvalidCiphertext
        | HpkeError::InvalidInputKeyMaterial
        | HpkeError::InvalidPsk
        | HpkeError::InvalidPskIdentifier
        | HpkeError::InvalidInfoLength
        | HpkeError::InvalidExporterLength
        | HpkeError::InvalidRandomness
        | HpkeError::SealFailed
        | HpkeError::OpenFailed
        | HpkeError::ExportFailed
        | HpkeError::KeyGenerationFailed => CryptoError::ExporterError,
        _ => CryptoError::ExporterError,
    }
}

fn map_receiver_export_error(error: HpkeError) -> CryptoError {
    match error {
        HpkeError::UnsupportedKem
        | HpkeError::UnsupportedKdf
        | HpkeError::UnsupportedAead
        | HpkeError::UnsupportedSuite => CryptoError::UnsupportedCiphersuite,
        HpkeError::InvalidPublicKey => CryptoError::InvalidPublicKey,
        HpkeError::InvalidPrivateKey
        | HpkeError::InvalidEncapsulatedKey
        | HpkeError::InvalidCiphertext => CryptoError::InvalidLength,
        HpkeError::LengthOverflow => CryptoError::TooMuchData,
        HpkeError::RandomnessUnavailable => CryptoError::InsufficientRandomness,
        HpkeError::InvalidInputKeyMaterial
        | HpkeError::InvalidPsk
        | HpkeError::InvalidPskIdentifier
        | HpkeError::InvalidInfoLength
        | HpkeError::InvalidExporterLength
        | HpkeError::InvalidRandomness
        | HpkeError::SealFailed
        | HpkeError::OpenFailed
        | HpkeError::ExportFailed
        | HpkeError::KeyGenerationFailed => CryptoError::ExporterError,
        _ => CryptoError::ExporterError,
    }
}

fn map_keygen_error(error: HpkeError) -> CryptoError {
    match error {
        HpkeError::UnsupportedKem
        | HpkeError::UnsupportedKdf
        | HpkeError::UnsupportedAead
        | HpkeError::UnsupportedSuite => CryptoError::UnsupportedCiphersuite,
        HpkeError::InvalidInputKeyMaterial => CryptoError::InvalidLength,
        HpkeError::RandomnessUnavailable => CryptoError::InsufficientRandomness,
        HpkeError::InvalidPublicKey
        | HpkeError::InvalidPrivateKey
        | HpkeError::InvalidEncapsulatedKey
        | HpkeError::InvalidCiphertext
        | HpkeError::InvalidPsk
        | HpkeError::InvalidPskIdentifier
        | HpkeError::InvalidInfoLength
        | HpkeError::InvalidExporterLength
        | HpkeError::LengthOverflow
        | HpkeError::SealFailed
        | HpkeError::OpenFailed
        | HpkeError::ExportFailed
        | HpkeError::KeyGenerationFailed
        | HpkeError::InvalidRandomness => CryptoError::CryptoLibraryError,
        _ => CryptoError::CryptoLibraryError,
    }
}

#[cfg(feature = "targeted-messages-draft")]
fn map_sender_setup_error(error: HpkeError) -> CryptoError {
    match error {
        HpkeError::UnsupportedKem
        | HpkeError::UnsupportedKdf
        | HpkeError::UnsupportedAead
        | HpkeError::UnsupportedSuite => CryptoError::UnsupportedCiphersuite,
        HpkeError::InvalidPublicKey => CryptoError::InvalidPublicKey,
        HpkeError::RandomnessUnavailable => CryptoError::InsufficientRandomness,
        HpkeError::LengthOverflow => CryptoError::TooMuchData,
        HpkeError::InvalidPrivateKey
        | HpkeError::InvalidEncapsulatedKey
        | HpkeError::InvalidCiphertext
        | HpkeError::InvalidInputKeyMaterial
        | HpkeError::InvalidPsk
        | HpkeError::InvalidPskIdentifier
        | HpkeError::InvalidInfoLength
        | HpkeError::InvalidExporterLength
        | HpkeError::InvalidRandomness
        | HpkeError::SealFailed
        | HpkeError::OpenFailed
        | HpkeError::ExportFailed
        | HpkeError::KeyGenerationFailed => CryptoError::SenderSetupError,
        _ => CryptoError::SenderSetupError,
    }
}

#[cfg(feature = "targeted-messages-draft")]
fn map_receiver_setup_error(error: HpkeError) -> CryptoError {
    match error {
        HpkeError::UnsupportedKem
        | HpkeError::UnsupportedKdf
        | HpkeError::UnsupportedAead
        | HpkeError::UnsupportedSuite => CryptoError::UnsupportedCiphersuite,
        HpkeError::InvalidPublicKey => CryptoError::InvalidPublicKey,
        HpkeError::InvalidPrivateKey
        | HpkeError::InvalidEncapsulatedKey
        | HpkeError::InvalidCiphertext => CryptoError::InvalidLength,
        HpkeError::LengthOverflow => CryptoError::TooMuchData,
        HpkeError::RandomnessUnavailable => CryptoError::InsufficientRandomness,
        HpkeError::InvalidInputKeyMaterial
        | HpkeError::InvalidPsk
        | HpkeError::InvalidPskIdentifier
        | HpkeError::InvalidInfoLength
        | HpkeError::InvalidExporterLength
        | HpkeError::InvalidRandomness
        | HpkeError::SealFailed
        | HpkeError::OpenFailed
        | HpkeError::ExportFailed
        | HpkeError::KeyGenerationFailed => CryptoError::ReceiverSetupError,
        _ => CryptoError::ReceiverSetupError,
    }
}

#[cfg(feature = "targeted-messages-draft")]
fn map_open_psk_error(error: HpkeError) -> CryptoError {
    match error {
        HpkeError::UnsupportedKem
        | HpkeError::UnsupportedKdf
        | HpkeError::UnsupportedAead
        | HpkeError::UnsupportedSuite => CryptoError::UnsupportedCiphersuite,
        HpkeError::InvalidPublicKey => CryptoError::InvalidPublicKey,
        HpkeError::InvalidPrivateKey
        | HpkeError::InvalidEncapsulatedKey
        | HpkeError::InvalidCiphertext
        | HpkeError::InvalidPsk
        | HpkeError::InvalidPskIdentifier
        | HpkeError::InvalidInfoLength
        | HpkeError::InvalidInputKeyMaterial
        | HpkeError::InvalidRandomness => CryptoError::InvalidLength,
        HpkeError::LengthOverflow => CryptoError::TooMuchData,
        HpkeError::RandomnessUnavailable => CryptoError::InsufficientRandomness,
        HpkeError::OpenFailed
        | HpkeError::SealFailed
        | HpkeError::ExportFailed
        | HpkeError::InvalidExporterLength
        | HpkeError::KeyGenerationFailed => CryptoError::HpkeDecryptionError,
        _ => CryptoError::HpkeDecryptionError,
    }
}
