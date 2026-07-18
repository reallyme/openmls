// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT

//! FF1-AES128 adapter required only by the virtual-clients draft.
//!
//! FF1 is an auxiliary draft primitive and is not part of the ReallyMe X-Wing
//! MLS ciphersuite. ReallyMe Crypto does not currently expose FF1, so this
//! optional feature uses the same audited `fpe` boundary as the upstream
//! OpenMLS providers.

use aes::Aes128;
use fpe::ff1::{BinaryNumeralString, FF1};
use openmls_traits::types::CryptoError;

const RADIX: u32 = 2;

pub(crate) fn encrypt(key: &[u8; 16], plaintext: u32) -> Result<u32, CryptoError> {
    let ff1 = FF1::<Aes128>::new(key, RADIX).map_err(|_| CryptoError::CryptoLibraryError)?;
    let input = BinaryNumeralString::from_bytes_le(&plaintext.to_be_bytes());
    let output = ff1
        .encrypt(&[], &input)
        .map_err(|_| CryptoError::CryptoLibraryError)?;
    numeral_string_to_u32(output)
}

pub(crate) fn decrypt(key: &[u8; 16], ciphertext: u32) -> Result<u32, CryptoError> {
    let ff1 = FF1::<Aes128>::new(key, RADIX).map_err(|_| CryptoError::CryptoLibraryError)?;
    let input = BinaryNumeralString::from_bytes_le(&ciphertext.to_be_bytes());
    let output = ff1
        .decrypt(&[], &input)
        .map_err(|_| CryptoError::CryptoLibraryError)?;
    numeral_string_to_u32(output)
}

fn numeral_string_to_u32(numeral_string: BinaryNumeralString) -> Result<u32, CryptoError> {
    let bytes = <[u8; 4]>::try_from(numeral_string.to_bytes_le())
        .map_err(|_| CryptoError::CryptoLibraryError)?;
    Ok(u32::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_vector_matches_other_openmls_providers() -> Result<(), CryptoError> {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = 0x0123_4567;
        let ciphertext = encrypt(&key, plaintext)?;
        assert_eq!(ciphertext, 0xa1ba_5e30);
        assert_eq!(decrypt(&key, ciphertext)?, plaintext);
        Ok(())
    }
}
