// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT

use openmls_traits::types::CryptoError;
use reallyme_crypto::{
    core::MacAlgorithm,
    hmac::{authenticate, HmacKey},
};
use zeroize::Zeroizing;

pub(crate) const SHA256_OUTPUT_LENGTH: usize = 32;
pub(crate) const SHA384_OUTPUT_LENGTH: usize = 48;
const HKDF_MAX_BLOCKS: usize = 255;

type HmacFunction = fn(&[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    hmac(MacAlgorithm::HmacSha256, SHA256_OUTPUT_LENGTH, key, message)
}

pub(crate) fn hmac_sha384(key: &[u8], message: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    hmac(MacAlgorithm::HmacSha384, SHA384_OUTPUT_LENGTH, key, message)
}

fn hmac(
    algorithm: MacAlgorithm,
    output_length: usize,
    key: &[u8],
    message: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // ReallyMe rejects an empty HMAC key at its public boundary. HMAC's key
    // normalization makes an empty key equivalent to a single zero byte for
    // every hash we expose: both are right-padded to the hash block size. This
    // preserves RFC 2104 behavior while retaining ReallyMe's typed key boundary.
    const EMPTY_KEY_EQUIVALENT: [u8; 1] = [0u8; 1];
    let normalized_key = if key.is_empty() {
        EMPTY_KEY_EQUIVALENT.as_slice()
    } else {
        key
    };
    let key = HmacKey::from_slice(normalized_key).map_err(|_| CryptoError::InvalidLength)?;
    let tag =
        authenticate(algorithm, &key, message).map_err(|_| CryptoError::CryptoLibraryError)?;
    if tag.as_bytes().len() != output_length {
        return Err(CryptoError::CryptoLibraryError);
    }
    Ok(Zeroizing::new(tag.into_vec()))
}

pub(crate) fn hkdf_extract_sha256(
    salt: &[u8],
    ikm: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    const ZERO_SALT: [u8; SHA256_OUTPUT_LENGTH] = [0u8; SHA256_OUTPUT_LENGTH];
    let normalized_salt = if salt.is_empty() {
        ZERO_SALT.as_slice()
    } else {
        salt
    };
    hmac_sha256(normalized_salt, ikm)
}

pub(crate) fn hkdf_extract_sha384(
    salt: &[u8],
    ikm: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    const ZERO_SALT: [u8; SHA384_OUTPUT_LENGTH] = [0u8; SHA384_OUTPUT_LENGTH];
    let normalized_salt = if salt.is_empty() {
        ZERO_SALT.as_slice()
    } else {
        salt
    };
    hmac_sha384(normalized_salt, ikm)
}

pub(crate) fn hkdf_expand_sha256(
    prk: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    hkdf_expand(SHA256_OUTPUT_LENGTH, hmac_sha256, prk, info, output_length)
}

pub(crate) fn hkdf_expand_sha384(
    prk: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    hkdf_expand(SHA384_OUTPUT_LENGTH, hmac_sha384, prk, info, output_length)
}

fn hkdf_expand(
    hash_output_length: usize,
    hmac_fn: HmacFunction,
    prk: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let maximum_length = hash_output_length
        .checked_mul(HKDF_MAX_BLOCKS)
        .ok_or(CryptoError::HkdfOutputLengthInvalid)?;
    if output_length > maximum_length {
        return Err(CryptoError::HkdfOutputLengthInvalid);
    }

    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(output_length)
        .map_err(|_| CryptoError::TooMuchData)?;
    if output_length == 0 {
        return Ok(output);
    }

    let rounded_length = output_length
        .checked_add(
            hash_output_length
                .checked_sub(1)
                .ok_or(CryptoError::HkdfOutputLengthInvalid)?,
        )
        .ok_or(CryptoError::HkdfOutputLengthInvalid)?;
    let block_count = rounded_length
        .checked_div(hash_output_length)
        .ok_or(CryptoError::HkdfOutputLengthInvalid)?;
    let mut previous = Zeroizing::new(Vec::new());

    for block_index in 1..=block_count {
        let input_capacity = previous
            .len()
            .checked_add(info.len())
            .and_then(|value| value.checked_add(1))
            .ok_or(CryptoError::TooMuchData)?;
        let mut block_input = Zeroizing::new(Vec::new());
        block_input
            .try_reserve_exact(input_capacity)
            .map_err(|_| CryptoError::TooMuchData)?;
        block_input.extend_from_slice(&previous);
        block_input.extend_from_slice(info);
        let counter =
            u8::try_from(block_index).map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
        block_input.push(counter);

        let block = hmac_fn(prk, &block_input)?;
        let remaining = output_length
            .checked_sub(output.len())
            .ok_or(CryptoError::HkdfOutputLengthInvalid)?;
        let take = remaining.min(hash_output_length);
        output.extend_from_slice(&block[..take]);

        previous.clear();
        previous.extend_from_slice(&block);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5869_sha256_case_one() -> Result<(), CryptoError> {
        let ikm = [0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c")
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        let info =
            hex::decode("f0f1f2f3f4f5f6f7f8f9").map_err(|_| CryptoError::CryptoLibraryError)?;
        let expected_prk = hex::decode(
            "077709362c2e32df0ddc3f0dc47bba63\
             90b6c73bb50f9c3122ec844ad7c2b3e5",
        )
        .map_err(|_| CryptoError::CryptoLibraryError)?;
        let expected_okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        )
        .map_err(|_| CryptoError::CryptoLibraryError)?;

        let prk = hkdf_extract_sha256(&salt, &ikm)?;
        assert_eq!(&*prk, &expected_prk);
        let okm = hkdf_expand_sha256(&prk, &info, 42)?;
        assert_eq!(&*okm, &expected_okm);
        Ok(())
    }

    #[test]
    fn sha384_independent_known_answer() -> Result<(), CryptoError> {
        // This vector is independently generated from the RFC 5869 test-case
        // inputs with HMAC-SHA384. Keeping it here catches accidental routing
        // to SHA-256 while exercising the exact MLS SHA-384 adapter path.
        let ikm = [0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c")
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        let info =
            hex::decode("f0f1f2f3f4f5f6f7f8f9").map_err(|_| CryptoError::CryptoLibraryError)?;
        let expected_prk = hex::decode(
            "704b39990779ce1dc548052c7dc39f30\
             3570dd13fb39f7acc564680bef80e8de\
             c70ee9a7e1f3e293ef68eceb072a5ade",
        )
        .map_err(|_| CryptoError::CryptoLibraryError)?;
        let expected_okm = hex::decode(
            "9b5097a86038b805309076a44b3a9f38\
             063e25b516dcbf369f394cfab43685f7\
             48b6457763e4f0204fc5",
        )
        .map_err(|_| CryptoError::CryptoLibraryError)?;

        let prk = hkdf_extract_sha384(&salt, &ikm)?;
        assert_eq!(&*prk, &expected_prk);
        let okm = hkdf_expand_sha384(&prk, &info, 42)?;
        assert_eq!(&*okm, &expected_okm);
        Ok(())
    }

    #[test]
    fn expand_rejects_oversized_output() -> Result<(), CryptoError> {
        let maximum = SHA256_OUTPUT_LENGTH
            .checked_mul(HKDF_MAX_BLOCKS)
            .ok_or(CryptoError::CryptoLibraryError)?;
        let oversized = maximum
            .checked_add(1)
            .ok_or(CryptoError::CryptoLibraryError)?;
        assert_eq!(
            hkdf_expand_sha256(&[1u8; SHA256_OUTPUT_LENGTH], &[], oversized),
            Err(CryptoError::HkdfOutputLengthInvalid)
        );
        Ok(())
    }
}
