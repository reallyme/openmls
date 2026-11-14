// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited
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
    HPKE_MLKEM768_HKDF_SHA384_AES256GCM, HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
    HPKE_XWING_HKDF_SHA384_AES256GCM,
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
fn reallyme_suite(config: &HpkeConfig) -> Result<HpkeSuite, CryptoError> {
    match (config.0, config.1, config.2) {
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        (HpkeKemType::XWingKemDraft6, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
            Ok(HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305)
        }
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        (HpkeKemType::XWingKemDraft6, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
            Ok(HPKE_XWING_HKDF_SHA384_AES256GCM)
        }
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        (HpkeKemType::MlKem768, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
            Ok(HPKE_MLKEM768_HKDF_SHA384_AES256GCM)
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
    // The patched hpke-rs dependency implements the current HPKE-PQ labeled
    // DeriveKeyPair procedure for X-Wing. Delegate every X-Wing profile to the
    // backend so ReallyMe and libcrux derive matching MLS tree key material.
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
    .map_err(|error| map_operation_error(error, CryptoError::ExporterError))?;
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
    .map_err(|error| map_receiver_error(error, CryptoError::ExporterError))?;
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
        .map_err(map_open_error)?;
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
    .map_err(|error| map_operation_error(error, CryptoError::SenderSetupError))?;
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
    .map_err(|error| map_receiver_error(error, CryptoError::ReceiverSetupError))
}

// Crypto 0.4 reports canonical reasons shared across primitives. Keep the MLS
// operation as the fallback so authentication and backend failures retain the
// error for the operation the caller invoked.
fn map_operation_error(error: HpkeError, operation_error: CryptoError) -> CryptoError {
    match error {
        HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM => CryptoError::UnsupportedCiphersuite,
        HpkeError::PRIMITIVE_INVALID_PUBLIC_KEY => CryptoError::InvalidPublicKey,
        HpkeError::PROVIDER_RANDOMNESS_UNAVAILABLE => CryptoError::InsufficientRandomness,
        HpkeError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED => CryptoError::TooMuchData,
        _ => operation_error,
    }
}

fn map_receiver_error(error: HpkeError, operation_error: CryptoError) -> CryptoError {
    match error {
        HpkeError::PRIMITIVE_INVALID_PRIVATE_KEY | HpkeError::PRIMITIVE_MALFORMED_CIPHERTEXT => {
            CryptoError::InvalidLength
        }
        _ => map_operation_error(error, operation_error),
    }
}

fn map_seal_error(error: HpkeError) -> CryptoError {
    match error {
        HpkeError::PRIMITIVE_INVALID_LENGTH | HpkeError::PRIMITIVE_INVALID_PARAMETER => {
            CryptoError::InvalidLength
        }
        _ => map_operation_error(error, CryptoError::HpkeEncryptionError),
    }
}

fn map_open_error(error: HpkeError) -> CryptoError {
    match error {
        HpkeError::PRIMITIVE_INVALID_LENGTH | HpkeError::PRIMITIVE_INVALID_PARAMETER => {
            CryptoError::InvalidLength
        }
        _ => map_receiver_error(error, CryptoError::HpkeDecryptionError),
    }
}

fn map_keygen_error(error: HpkeError) -> CryptoError {
    match error {
        HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM => CryptoError::UnsupportedCiphersuite,
        HpkeError::PROVIDER_RANDOMNESS_UNAVAILABLE => CryptoError::InsufficientRandomness,
        HpkeError::PRIMITIVE_INVALID_LENGTH => CryptoError::InvalidLength,
        _ => CryptoError::CryptoLibraryError,
    }
}
