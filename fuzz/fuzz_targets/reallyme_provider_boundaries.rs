// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT

#![no_main]

use libfuzzer_sys::fuzz_target;
use openmls_reallyme_provider::CryptoProvider;
use openmls_traits::{
    crypto::OpenMlsCrypto as _,
    types::{Ciphersuite, HpkeCiphertext, SignatureScheme},
};

fn three_way_split(input: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    // Independent lengths are essential: Ed25519 requires a 32-byte public
    // key and a 64-byte signature, while PQ encapsulations dwarf secret seeds.
    // A fixed header also lets the spot-fuzz corpus seed those exact shapes.
    let (lengths, body) = input.split_first_chunk::<4>()?;
    let first_length = usize::from(u16::from_le_bytes([lengths[0], lengths[1]]));
    let second_length = usize::from(u16::from_le_bytes([lengths[2], lengths[3]]));
    let (first, rest) = body.split_at_checked(first_length)?;
    let (second, third) = rest.split_at_checked(second_length)?;
    Some((first, second, third))
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let Some((first, second, third)) = three_way_split(body) else {
        return;
    };
    let crypto = CryptoProvider;

    if selector & 1 == 0 {
        let ciphersuite = match (selector / 2) % 6 {
            0 => Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            1 => Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
            2 => Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
            3 => Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
            4 => Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
            _ => Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
        };
        let ciphertext = HpkeCiphertext {
            kem_output: first.to_vec().into(),
            ciphertext: second.to_vec().into(),
        };
        let _ = crypto.hpke_open(
            ciphersuite.hpke_config(),
            &ciphertext,
            third,
            b"fuzzed ReallyMe HPKE info",
            b"fuzzed ReallyMe HPKE aad",
        );
    } else {
        let signature_scheme = match (selector / 2) % 4 {
            0 => SignatureScheme::ED25519,
            1 => SignatureScheme::ECDSA_SECP384R1_SHA384,
            2 => SignatureScheme::MLDSA65,
            _ => SignatureScheme::MLDSA87,
        };
        let _ = crypto.verify_signature(signature_scheme, first, second, third);
    }
});
