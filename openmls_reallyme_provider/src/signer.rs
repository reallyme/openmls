use std::fmt;

use openmls_traits::{
    signatures::{Signer, SignerError},
    types::{CryptoError, SignatureScheme},
};
use reallyme_crypto::ed25519::sign_ed25519;
use secrecy::{ExposeSecret, SecretBox};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::generate_signature_keypair;

const ED25519_SEED_LENGTH: usize = 32;

/// Ed25519 signer backed by ReallyMe Crypto.
///
/// The secret seed is held in a secrecy wrapper and zeroized with the signer.
/// The type intentionally does not implement `Clone` or expose raw secret bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ReallyMeSigner {
    secret_seed: SecretBox<[u8; ED25519_SEED_LENGTH]>,
    public_key: [u8; ED25519_SEED_LENGTH],
}

impl ReallyMeSigner {
    /// Generate a signer from the ReallyMe operating-system CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let (private, public) = generate_signature_keypair()?;
        if private.len() != ED25519_SEED_LENGTH {
            return Err(CryptoError::CryptoLibraryError);
        }
        let secret_seed = SecretBox::init_with_mut(|seed: &mut [u8; ED25519_SEED_LENGTH]| {
            seed.copy_from_slice(&private);
        });
        let public_key = <[u8; ED25519_SEED_LENGTH]>::try_from(public)
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        Ok(Self {
            secret_seed,
            public_key,
        })
    }

    /// Construct a signer from a caller-owned secret seed.
    #[cfg(not(all(feature = "wasm", target_arch = "wasm32", not(feature = "native"))))]
    pub fn from_secret_seed(
        secret_seed: SecretBox<[u8; ED25519_SEED_LENGTH]>,
    ) -> Result<Self, CryptoError> {
        let (public_key, derived_private) =
            reallyme_crypto::ed25519::generate_ed25519_keypair_from_seed(
                secret_seed.expose_secret(),
            );
        // The deterministic ReallyMe API returns the input seed as a second,
        // zeroizing value. Drop it immediately; this signer retains only the
        // caller's secrecy-wrapped seed.
        drop(derived_private);
        let public_key = <[u8; ED25519_SEED_LENGTH]>::try_from(public_key)
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        Ok(Self {
            secret_seed,
            public_key,
        })
    }

    /// Return the public verification key.
    pub fn public_key(&self) -> &[u8; ED25519_SEED_LENGTH] {
        &self.public_key
    }
}

impl fmt::Debug for ReallyMeSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReallyMeSigner")
            .field("secret_seed", &"[REDACTED]")
            .field("public_key_length", &self.public_key.len())
            .finish()
    }
}

impl Signer for ReallyMeSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        sign_ed25519(self.secret_seed.expose_secret(), payload)
            .map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[cfg(test)]
mod tests {
    use openmls_traits::{crypto::OpenMlsCrypto as _, signatures::Signer as _};

    use super::*;
    use crate::CryptoProvider;

    #[test]
    fn signer_round_trip_uses_reallyme_verification() -> Result<(), CryptoError> {
        let signer = ReallyMeSigner::generate()?;
        let payload = b"reallyme-openmls-signer-test";
        let signature = signer
            .sign(payload)
            .map_err(|_| CryptoError::SigningError)?;
        CryptoProvider.verify_signature(
            SignatureScheme::ED25519,
            payload,
            signer.public_key(),
            &signature,
        )
    }
}
