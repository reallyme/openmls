#[cfg(feature = "targeted-messages-draft")]
use openmls_traits::crypto::HpkeSealPskResolvedAadError;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
        HpkeKeyPair, KemOutput, SignatureScheme,
    },
};
use reallyme_crypto::{
    chacha20_poly1305::{
        decrypt, encrypt, ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, CiphertextWithTag,
        DecryptRequest, EncryptRequest, CHACHA20_POLY1305_KEY_LENGTH,
        CHACHA20_POLY1305_NONCE_LENGTH, CHACHA20_POLY1305_TAG_LENGTH,
    },
    ed25519::{sign_ed25519, verify_ed25519},
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
    let (public, private) = reallyme_crypto::ed25519::generate_ed25519_keypair_from_seed(&seed);
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

impl OpenMlsCrypto for CryptoProvider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        if ciphersuite == Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 {
            return Ok(());
        }
        let _ = ciphersuite;
        Err(CryptoError::UnsupportedCiphersuite)
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        {
            vec![Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519]
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
        if hash_type != HashType::Sha2_256 {
            return Err(CryptoError::UnsupportedHashAlgorithm);
        }
        kdf::hkdf_extract_sha256(salt, ikm).map(|secret| secret.to_vec().into())
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        if hash_type != HashType::Sha2_256 {
            return Err(CryptoError::UnsupportedHashAlgorithm);
        }
        kdf::hmac_sha256(key, message).map(|tag| tag.to_vec().into())
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        if hash_type != HashType::Sha2_256 {
            return Err(CryptoError::UnsupportedHashAlgorithm);
        }
        kdf::hkdf_expand_sha256(prk, info, okm_len).map(|secret| secret.to_vec().into())
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if hash_type != HashType::Sha2_256 {
            return Err(CryptoError::UnsupportedHashAlgorithm);
        }
        Ok(sha2::digest(data).as_bytes().to_vec())
    }

    fn aead_encrypt(
        &self,
        algorithm: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if algorithm != AeadType::ChaCha20Poly1305 {
            return Err(CryptoError::UnsupportedAeadAlgorithm);
        }
        chacha_encrypt(key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        algorithm: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if algorithm != AeadType::ChaCha20Poly1305 {
            return Err(CryptoError::UnsupportedAeadAlgorithm);
        }
        chacha_decrypt(key, ct_tag, nonce, aad)
    }

    fn signature_key_gen(
        &self,
        algorithm: SignatureScheme,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if algorithm != SignatureScheme::ED25519 {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }
        let (private, public) = generate_signature_keypair()?;
        Ok((private.as_slice().to_vec(), public))
    }

    fn verify_signature(
        &self,
        algorithm: SignatureScheme,
        data: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if algorithm != SignatureScheme::ED25519 {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }
        if public_key.len() != ED25519_PUBLIC_KEY_LENGTH {
            return Err(CryptoError::InvalidPublicKey);
        }
        if signature.len() != ED25519_SIGNATURE_LENGTH {
            return Err(CryptoError::InvalidSignature);
        }
        verify_ed25519(public_key, data, signature).map_err(|_| CryptoError::InvalidSignature)
    }

    fn sign(
        &self,
        algorithm: SignatureScheme,
        data: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if algorithm != SignatureScheme::ED25519 {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }
        if key.len() != ED25519_PRIVATE_KEY_LENGTH {
            return Err(CryptoError::InvalidLength);
        }
        sign_ed25519(key, data).map_err(|_| CryptoError::SigningError)
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
        let (kem_output, context) = hpke::setup_sender_psk(config, pk_r, info, psk, psk_id)
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
