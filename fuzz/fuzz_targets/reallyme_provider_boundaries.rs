#![no_main]

use libfuzzer_sys::fuzz_target;
use openmls_reallyme_provider::CryptoProvider;
use openmls_traits::{
    crypto::OpenMlsCrypto as _,
    types::{Ciphersuite, HpkeCiphertext, SignatureScheme},
};

fn three_way_split(input: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let first_end = input.len() / 3;
    let second_end = first_end.checked_mul(2)?;
    Some((
        input.get(..first_end)?,
        input.get(first_end..second_end)?,
        input.get(second_end..)?,
    ))
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
        let ciphersuite = match (selector / 2) % 4 {
            0 => Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            1 => Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
            2 => Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
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
        let signature_scheme = match (selector / 2) % 3 {
            0 => SignatureScheme::ED25519,
            1 => SignatureScheme::ECDSA_SECP384R1_SHA384,
            _ => SignatureScheme::MLDSA87,
        };
        let _ = crypto.verify_signature(signature_scheme, first, second, third);
    }
});
