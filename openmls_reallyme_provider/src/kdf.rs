use openmls_traits::types::CryptoError;
use reallyme_crypto::{
    core::MacAlgorithm,
    hmac::{authenticate, HmacKey},
};
use zeroize::Zeroizing;

pub(crate) const SHA256_OUTPUT_LENGTH: usize = 32;
const HKDF_MAX_BLOCKS: usize = 255;

pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // ReallyMe rejects an empty HMAC key at its public boundary. HMAC's key
    // normalization makes an empty key equivalent to a single zero byte: both
    // become an all-zero SHA-256 block. This preserves RFC 2104 behavior while
    // retaining ReallyMe's typed key boundary.
    const EMPTY_KEY_EQUIVALENT: [u8; 1] = [0u8; 1];
    let normalized_key = if key.is_empty() {
        EMPTY_KEY_EQUIVALENT.as_slice()
    } else {
        key
    };
    let key = HmacKey::from_slice(normalized_key).map_err(|_| CryptoError::InvalidLength)?;
    let tag = authenticate(MacAlgorithm::HmacSha256, &key, message)
        .map_err(|_| CryptoError::CryptoLibraryError)?;
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

pub(crate) fn hkdf_expand_sha256(
    prk: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let maximum_length = SHA256_OUTPUT_LENGTH
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
        .checked_add(SHA256_OUTPUT_LENGTH - 1)
        .ok_or(CryptoError::HkdfOutputLengthInvalid)?;
    let block_count = rounded_length / SHA256_OUTPUT_LENGTH;
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

        let block = hmac_sha256(prk, &block_input)?;
        let remaining = output_length
            .checked_sub(output.len())
            .ok_or(CryptoError::HkdfOutputLengthInvalid)?;
        let take = remaining.min(SHA256_OUTPUT_LENGTH);
        output.extend_from_slice(&block[..take]);

        previous.clear();
        previous.extend_from_slice(&block);
    }

    Ok(output)
}

pub(crate) fn checked_concat(parts: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let capacity = parts.iter().try_fold(0usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or(CryptoError::TooMuchData)
    })?;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(capacity)
        .map_err(|_| CryptoError::TooMuchData)?;
    for part in parts {
        output.extend_from_slice(part);
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
