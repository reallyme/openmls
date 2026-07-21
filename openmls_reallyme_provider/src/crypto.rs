// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT

#[cfg(feature = "targeted-messages-draft")]
use openmls_traits::crypto::HpkeSealPskResolvedAadError;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
        HpkeKeyPair, KemOutput, SignatureScheme,
    },
};
#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
use reallyme_crypto::ml_dsa_87::{
    generate_ml_dsa_87_keypair, sign_ml_dsa_87, verify_ml_dsa_87, ML_DSA_87_PUBLIC_KEY_LEN,
    ML_DSA_87_SECRET_SEED_LEN, ML_DSA_87_SIGNATURE_LEN,
};
use reallyme_crypto::{
    aes256_gcm::{
        aes256_gcm_decrypt, aes256_gcm_encrypt, Aes256GcmKey, Aes256GcmNonce,
        CiphertextWithTag as Aes256GcmCiphertextWithTag, AES_256_GCM_KEY_LEN,
        AES_256_GCM_NONCE_LEN, AES_256_GCM_TAG_LEN,
    },
    chacha20_poly1305::{
        decrypt, encrypt, ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, CiphertextWithTag,
        DecryptRequest, EncryptRequest, CHACHA20_POLY1305_KEY_LENGTH,
        CHACHA20_POLY1305_NONCE_LENGTH, CHACHA20_POLY1305_TAG_LENGTH,
    },
    ed25519::{sign_ed25519, verify_ed25519},
    p384::{
        decompress_public_key as decompress_p384_public_key, generate_p384_keypair,
        sign as sign_p384, verify as verify_p384, P384_PUBLIC_KEY_UNCOMPRESSED_LEN,
        P384_SECRET_KEY_LEN,
    },
    sha2,
};
use tls_codec::SecretVLBytes;
use zeroize::Zeroizing;

use crate::{hpke, kdf};

const ED25519_PRIVATE_KEY_LENGTH: usize = 32;
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
const ED25519_SIGNATURE_LENGTH: usize = 64;

#[cfg(not(all(feature = "wasm", target_arch = "wasm32", not(feature = "native"))))]
pub(crate) fn generate_signature_keypair() -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CryptoError> {
    let mut seed = Zeroizing::new([0u8; ED25519_PRIVATE_KEY_LENGTH]);
    CryptoProvider::fill_random(&mut *seed).map_err(|_| CryptoError::InsufficientRandomness)?;
    let (public, private) = reallyme_crypto::ed25519::generate_ed25519_keypair_from_seed(&seed)
        .map_err(|_| CryptoError::InsufficientRandomness)?;
    Ok((private, public))
}

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
pub(crate) fn generate_signature_keypair() -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CryptoError> {
    reallyme_crypto::ed25519::generate_ed25519_keypair()
        .map(|(public, private)| (private, public))
        .map_err(|_| CryptoError::InsufficientRandomness)
}

/// Stateless ReallyMe cryptography and randomness provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct CryptoProvider;

pub(crate) fn chacha_encrypt(
    key: &[u8],
    plaintext: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != CHACHA20_POLY1305_KEY_LENGTH || nonce.len() != CHACHA20_POLY1305_NONCE_LENGTH {
        return Err(CryptoError::InvalidLength);
    }
    plaintext
        .len()
        .checked_add(CHACHA20_POLY1305_TAG_LENGTH)
        .ok_or(CryptoError::TooMuchData)?;
    let key = ChaCha20Poly1305Key::from_slice(key).map_err(|_| CryptoError::InvalidLength)?;
    let nonce = ChaCha20Poly1305Nonce::from_slice(nonce).map_err(|_| CryptoError::InvalidLength)?;
    encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad,
        plaintext,
    })
    .map(CiphertextWithTag::into_vec)
    .map_err(|_| CryptoError::CryptoLibraryError)
}

pub(crate) fn chacha_decrypt(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != CHACHA20_POLY1305_KEY_LENGTH
        || nonce.len() != CHACHA20_POLY1305_NONCE_LENGTH
        || ciphertext.len() < CHACHA20_POLY1305_TAG_LENGTH
    {
        return Err(CryptoError::InvalidLength);
    }
    let key = ChaCha20Poly1305Key::from_slice(key).map_err(|_| CryptoError::InvalidLength)?;
    let nonce = ChaCha20Poly1305Nonce::from_slice(nonce).map_err(|_| CryptoError::InvalidLength)?;
    let ciphertext =
        CiphertextWithTag::from_vec(ciphertext.to_vec()).map_err(|_| CryptoError::InvalidLength)?;
    decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad,
        ciphertext: &ciphertext,
    })
    .map_err(|_| CryptoError::AeadDecryptionError)
}

fn aes256_gcm_encrypt_adapter(
    key: &[u8],
    plaintext: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != AES_256_GCM_KEY_LEN || nonce.len() != AES_256_GCM_NONCE_LEN {
        return Err(CryptoError::InvalidLength);
    }
    plaintext
        .len()
        .checked_add(AES_256_GCM_TAG_LEN)
        .ok_or(CryptoError::TooMuchData)?;
    let key = Aes256GcmKey::from_slice(key).map_err(|_| CryptoError::InvalidLength)?;
    let nonce = Aes256GcmNonce::from_slice(nonce).map_err(|_| CryptoError::InvalidLength)?;
    aes256_gcm_encrypt(&key, nonce, aad, plaintext)
        .map(Aes256GcmCiphertextWithTag::into_vec)
        .map_err(|_| CryptoError::CryptoLibraryError)
}

fn aes256_gcm_decrypt_adapter(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != AES_256_GCM_KEY_LEN
        || nonce.len() != AES_256_GCM_NONCE_LEN
        || ciphertext.len() < AES_256_GCM_TAG_LEN
    {
        return Err(CryptoError::InvalidLength);
    }
    let key = Aes256GcmKey::from_slice(key).map_err(|_| CryptoError::InvalidLength)?;
    let nonce = Aes256GcmNonce::from_slice(nonce).map_err(|_| CryptoError::InvalidLength)?;
    let ciphertext = Aes256GcmCiphertextWithTag::from_vec(ciphertext.to_vec())
        .map_err(|_| CryptoError::InvalidLength)?;
    aes256_gcm_decrypt(&key, nonce, aad, &ciphertext).map_err(|_| CryptoError::AeadDecryptionError)
}

impl OpenMlsCrypto for CryptoProvider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        {
            match ciphersuite {
                Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
                | Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384
                | Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87
                | Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384 => return Ok(()),
                _ => {}
            }
        }
        let _ = ciphersuite;
        Err(CryptoError::UnsupportedCiphersuite)
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        {
            vec![Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519]
                .into_iter()
                .chain([
                    Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
                    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
                    Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
                ])
                .collect()
        }
        #[cfg(not(feature = "draft-ietf-mls-pq-ciphersuites"))]
        {
            Vec::new()
        }
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        match hash_type {
            HashType::Sha2_256 => kdf::hkdf_extract_sha256(salt, ikm),
            HashType::Sha2_384 => kdf::hkdf_extract_sha384(salt, ikm),
            HashType::Sha2_512 => return Err(CryptoError::UnsupportedHashAlgorithm),
        }
        .map(|secret| secret.to_vec().into())
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        match hash_type {
            HashType::Sha2_256 => kdf::hmac_sha256(key, message),
            HashType::Sha2_384 => kdf::hmac_sha384(key, message),
            HashType::Sha2_512 => return Err(CryptoError::UnsupportedHashAlgorithm),
        }
        .map(|tag| tag.to_vec().into())
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        match hash_type {
            HashType::Sha2_256 => kdf::hkdf_expand_sha256(prk, info, okm_len),
            HashType::Sha2_384 => kdf::hkdf_expand_sha384(prk, info, okm_len),
            HashType::Sha2_512 => return Err(CryptoError::UnsupportedHashAlgorithm),
        }
        .map(|secret| secret.to_vec().into())
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match hash_type {
            HashType::Sha2_256 => Ok(sha2::digest(data).as_bytes().to_vec()),
            HashType::Sha2_384 => Ok(sha2::digest_sha2_384(data).as_bytes().to_vec()),
            HashType::Sha2_512 => Err(CryptoError::UnsupportedHashAlgorithm),
        }
    }

    fn aead_encrypt(
        &self,
        algorithm: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match algorithm {
            AeadType::ChaCha20Poly1305 => chacha_encrypt(key, data, nonce, aad),
            AeadType::Aes256Gcm => aes256_gcm_encrypt_adapter(key, data, nonce, aad),
            AeadType::Aes128Gcm => Err(CryptoError::UnsupportedAeadAlgorithm),
        }
    }

    fn aead_decrypt(
        &self,
        algorithm: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match algorithm {
            AeadType::ChaCha20Poly1305 => chacha_decrypt(key, ct_tag, nonce, aad),
            AeadType::Aes256Gcm => aes256_gcm_decrypt_adapter(key, ct_tag, nonce, aad),
            AeadType::Aes128Gcm => Err(CryptoError::UnsupportedAeadAlgorithm),
        }
    }

    fn signature_key_gen(
        &self,
        algorithm: SignatureScheme,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        match algorithm {
            SignatureScheme::ED25519 => {
                let (private, public) = generate_signature_keypair()?;
                Ok((private.as_slice().to_vec(), public))
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let (public, private) =
                    generate_p384_keypair().map_err(|_| CryptoError::InsufficientRandomness)?;
                let public = decompress_p384_public_key(&public)
                    .map_err(|_| CryptoError::InvalidPublicKey)?;
                Ok((private.as_slice().to_vec(), public))
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA87 => generate_ml_dsa_87_keypair()
                .map(|(public, private)| (private.as_slice().to_vec(), public))
                .map_err(|_| CryptoError::InsufficientRandomness),
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn verify_signature(
        &self,
        algorithm: SignatureScheme,
        data: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        match algorithm {
            SignatureScheme::ED25519 => {
                if public_key.len() != ED25519_PUBLIC_KEY_LENGTH {
                    return Err(CryptoError::InvalidPublicKey);
                }
                if signature.len() != ED25519_SIGNATURE_LENGTH {
                    return Err(CryptoError::InvalidSignature);
                }
                verify_ed25519(public_key, data, signature)
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                if public_key.len() != P384_PUBLIC_KEY_UNCOMPRESSED_LEN {
                    return Err(CryptoError::InvalidPublicKey);
                }
                verify_p384(public_key, data, signature).map_err(|_| CryptoError::InvalidSignature)
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA87 => {
                if public_key.len() != ML_DSA_87_PUBLIC_KEY_LEN {
                    return Err(CryptoError::InvalidPublicKey);
                }
                if signature.len() != ML_DSA_87_SIGNATURE_LEN {
                    return Err(CryptoError::InvalidSignature);
                }
                verify_ml_dsa_87(public_key, data, signature)
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn sign(
        &self,
        algorithm: SignatureScheme,
        data: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match algorithm {
            SignatureScheme::ED25519 => {
                if key.len() != ED25519_PRIVATE_KEY_LENGTH {
                    return Err(CryptoError::InvalidLength);
                }
                sign_ed25519(key, data).map_err(|_| CryptoError::SigningError)
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                if key.len() != P384_SECRET_KEY_LEN {
                    return Err(CryptoError::InvalidLength);
                }
                sign_p384(key, data).map_err(|_| CryptoError::SigningError)
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA87 => {
                if key.len() != ML_DSA_87_SECRET_SEED_LEN {
                    return Err(CryptoError::InvalidLength);
                }
                sign_ml_dsa_87(key, data).map_err(|_| CryptoError::SigningError)
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        hpke::seal(config, pk_r, info, aad, ptxt)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        hpke::open(config, input, sk_r, info, aad)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        hpke::sender_export(config, pk_r, info, exporter_context, exporter_length)
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        hpke::receiver_export(config, enc, sk_r, info, exporter_context, exporter_length)
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        hpke::derive_keypair(config, ikm)
    }

    #[cfg(feature = "targeted-messages-draft")]
    fn hpke_open_psk(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        hpke::open_psk(config, input, sk_r, info, aad, psk, psk_id)
    }

    #[cfg(feature = "targeted-messages-draft")]
    fn hpke_seal_psk_resolved_aad<F, E>(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        ptxt: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        aad_builder: F,
    ) -> Result<HpkeCiphertext, HpkeSealPskResolvedAadError<E>>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    {
        let (kem_output, mut context) = hpke::setup_sender_psk(config, pk_r, info, psk, psk_id)
            .map_err(HpkeSealPskResolvedAadError::CryptoError)?;
        let aad = aad_builder(&kem_output).map_err(HpkeSealPskResolvedAadError::AadBuildError)?;
        let ciphertext = context.seal(&aad, ptxt).map_err(|_| {
            HpkeSealPskResolvedAadError::CryptoError(CryptoError::HpkeEncryptionError)
        })?;
        Ok(HpkeCiphertext {
            kem_output: kem_output.into(),
            ciphertext: ciphertext.into(),
        })
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn ff1_aes128_encrypt(&self, key: &[u8; 16], plaintext: u32) -> Result<u32, CryptoError> {
        crate::ff1::encrypt(key, plaintext)
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn ff1_aes128_decrypt(&self, key: &[u8; 16], ciphertext: u32) -> Result<u32, CryptoError> {
        crate::ff1::decrypt(key, ciphertext)
    }
}
