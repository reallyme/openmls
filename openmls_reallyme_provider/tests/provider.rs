// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT

//! Provider boundary, interoperability, invalid-input, and MLS flow tests.

#![cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
#![allow(clippy::expect_used)]

use openmls_reallyme_provider::CryptoProvider;
use openmls_traits::{
    crypto::OpenMlsCrypto as _,
    random::OpenMlsRand as _,
    types::{AeadType, Ciphersuite, CryptoError, SignatureScheme},
};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const PURE_MLKEM1024_P384_SUITE: Ciphersuite = Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384;
const CNSA_MLKEM1024_MLDSA87_SUITE: Ciphersuite =
    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;
const HYBRID_MLKEM1024_P384_SUITE: Ciphersuite =
    Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384;

#[test]
fn advertises_only_reallyme_reviewed_suites() {
    let crypto = CryptoProvider;
    assert_eq!(
        crypto.supported_ciphersuites(),
        vec![
            CIPHERSUITE,
            PURE_MLKEM1024_P384_SUITE,
            CNSA_MLKEM1024_MLDSA87_SUITE,
            HYBRID_MLKEM1024_P384_SUITE,
        ]
    );
    for ciphersuite in crypto.supported_ciphersuites() {
        assert_eq!(crypto.supports(ciphersuite), Ok(()));
    }
    assert_eq!(
        crypto.supports(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
        Err(CryptoError::UnsupportedCiphersuite)
    );
}

#[test]
fn primitive_boundaries_reject_invalid_and_tampered_input() {
    let crypto = CryptoProvider;
    let key = [0x11; 32];
    let nonce = [0x22; 12];
    let aad = b"reallyme-aad";
    let plaintext = b"reallyme-plaintext";

    let mut ciphertext = crypto
        .aead_encrypt(AeadType::ChaCha20Poly1305, &key, plaintext, &nonce, aad)
        .expect("valid ReallyMe AEAD encryption should succeed");
    assert_eq!(
        crypto
            .aead_decrypt(AeadType::ChaCha20Poly1305, &key, &ciphertext, &nonce, aad,)
            .expect("valid ReallyMe AEAD decryption should succeed"),
        plaintext
    );
    let last = ciphertext
        .last_mut()
        .expect("AEAD ciphertext always includes an authentication tag");
    *last ^= 0x01;
    assert_eq!(
        crypto.aead_decrypt(AeadType::ChaCha20Poly1305, &key, &ciphertext, &nonce, aad,),
        Err(CryptoError::AeadDecryptionError)
    );
    assert_eq!(
        crypto.aead_encrypt(
            AeadType::ChaCha20Poly1305,
            &[0u8; 31],
            plaintext,
            &nonce,
            aad,
        ),
        Err(CryptoError::InvalidLength)
    );

    let aes_key = [0x33; 32];
    let aes_nonce = [0x44; 12];
    let aes_ciphertext = crypto
        .aead_encrypt(AeadType::Aes256Gcm, &aes_key, plaintext, &aes_nonce, aad)
        .expect("valid ReallyMe AES-256-GCM encryption should succeed");
    assert_eq!(
        crypto
            .aead_decrypt(
                AeadType::Aes256Gcm,
                &aes_key,
                &aes_ciphertext,
                &aes_nonce,
                aad
            )
            .expect("valid ReallyMe AES-256-GCM decryption should succeed"),
        plaintext
    );

    let (secret, public) = crypto
        .signature_key_gen(SignatureScheme::ED25519)
        .expect("valid ReallyMe Ed25519 key generation should succeed");
    let signature = crypto
        .sign(SignatureScheme::ED25519, plaintext, &secret)
        .expect("valid ReallyMe Ed25519 signing should succeed");
    crypto
        .verify_signature(SignatureScheme::ED25519, plaintext, &public, &signature)
        .expect("valid ReallyMe Ed25519 verification should succeed");
    assert_eq!(
        crypto.verify_signature(SignatureScheme::ED25519, b"tampered", &public, &signature,),
        Err(CryptoError::InvalidSignature)
    );
    assert_eq!(
        crypto.verify_signature(SignatureScheme::ED25519, plaintext, &[0u8; 31], &signature),
        Err(CryptoError::InvalidPublicKey)
    );

    let (p384_secret, p384_public) = crypto
        .signature_key_gen(SignatureScheme::ECDSA_SECP384R1_SHA384)
        .expect("valid ReallyMe P-384 key generation should succeed");
    let p384_signature = crypto
        .sign(
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            plaintext,
            &p384_secret,
        )
        .expect("valid ReallyMe P-384 signing should succeed");
    crypto
        .verify_signature(
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            plaintext,
            &p384_public,
            &p384_signature,
        )
        .expect("valid ReallyMe P-384 verification should succeed");

    let (ml_dsa_secret, ml_dsa_public) = crypto
        .signature_key_gen(SignatureScheme::MLDSA87)
        .expect("valid ReallyMe ML-DSA-87 key generation should succeed");
    let ml_dsa_signature = crypto
        .sign(SignatureScheme::MLDSA87, plaintext, &ml_dsa_secret)
        .expect("valid ReallyMe ML-DSA-87 signing should succeed");
    crypto
        .verify_signature(
            SignatureScheme::MLDSA87,
            plaintext,
            &ml_dsa_public,
            &ml_dsa_signature,
        )
        .expect("valid ReallyMe ML-DSA-87 verification should succeed");
}

#[test]
fn reallyme_hpke_round_trips_new_mlkem1024_suites() {
    let crypto = CryptoProvider;
    for ciphersuite in [
        PURE_MLKEM1024_P384_SUITE,
        CNSA_MLKEM1024_MLDSA87_SUITE,
        HYBRID_MLKEM1024_P384_SUITE,
    ] {
        let keypair = crypto
            .derive_hpke_keypair(
                ciphersuite.hpke_config(),
                b"reallyme-openmls-mlkem1024-key-material",
            )
            .expect("deterministic ReallyMe ML-KEM-1024 key derivation should succeed");
        let ciphertext = crypto
            .hpke_seal(
                ciphersuite.hpke_config(),
                &keypair.public,
                b"reallyme-pq-hpke-info",
                b"reallyme-pq-hpke-aad",
                b"reallyme-pq-hpke-payload",
            )
            .expect("ReallyMe HPKE seal should succeed");
        assert_eq!(
            crypto
                .hpke_open(
                    ciphersuite.hpke_config(),
                    &ciphertext,
                    &keypair.private,
                    b"reallyme-pq-hpke-info",
                    b"reallyme-pq-hpke-aad",
                )
                .expect("ReallyMe HPKE open should succeed"),
            b"reallyme-pq-hpke-payload"
        );

        let (encapsulation, sender_export) = crypto
            .hpke_setup_sender_and_export(
                ciphersuite.hpke_config(),
                &keypair.public,
                b"reallyme-pq-export-info",
                b"reallyme-pq-export-context",
                ciphersuite.hash_length(),
            )
            .expect("ReallyMe sender export should succeed");
        let receiver_export = crypto
            .hpke_setup_receiver_and_export(
                ciphersuite.hpke_config(),
                &encapsulation,
                &keypair.private,
                b"reallyme-pq-export-info",
                b"reallyme-pq-export-context",
                ciphersuite.hash_length(),
            )
            .expect("ReallyMe receiver export should succeed");
        assert_eq!(&*sender_export, &*receiver_export);
    }
}

#[test]
#[cfg(feature = "interop-tests")]
fn reallyme_hpke_interoperates_with_existing_libcrux_provider() {
    let reallyme = CryptoProvider;
    let libcrux = openmls_libcrux_crypto::CryptoProvider::new()
        .expect("libcrux test provider initialization should succeed");
    let ikm = b"reallyme-openmls-xwing-key-derivation-input";
    let reallyme_keypair = reallyme
        .derive_hpke_keypair(CIPHERSUITE.hpke_config(), ikm)
        .expect("ReallyMe X-Wing key derivation should succeed");
    let libcrux_keypair = libcrux
        .derive_hpke_keypair(CIPHERSUITE.hpke_config(), ikm)
        .expect("libcrux X-Wing key derivation should succeed");
    assert_eq!(reallyme_keypair.public, libcrux_keypair.public);
    assert_eq!(&*reallyme_keypair.private, &*libcrux_keypair.private);

    let info = b"reallyme-openmls-hpke-info";
    let aad = b"reallyme-openmls-hpke-aad";
    let plaintext = b"cross-provider HPKE payload";
    let from_reallyme = reallyme
        .hpke_seal(
            CIPHERSUITE.hpke_config(),
            &libcrux_keypair.public,
            info,
            aad,
            plaintext,
        )
        .expect("ReallyMe HPKE encryption should succeed");
    assert_eq!(
        libcrux
            .hpke_open(
                CIPHERSUITE.hpke_config(),
                &from_reallyme,
                &libcrux_keypair.private,
                info,
                aad,
            )
            .expect("libcrux should decrypt ReallyMe HPKE output"),
        plaintext
    );

    let from_libcrux = libcrux
        .hpke_seal(
            CIPHERSUITE.hpke_config(),
            &reallyme_keypair.public,
            info,
            aad,
            plaintext,
        )
        .expect("libcrux HPKE encryption should succeed");
    assert_eq!(
        reallyme
            .hpke_open(
                CIPHERSUITE.hpke_config(),
                &from_libcrux,
                &reallyme_keypair.private,
                info,
                aad,
            )
            .expect("ReallyMe should decrypt libcrux HPKE output"),
        plaintext
    );

    let exporter_context = b"reallyme-openmls-exporter";
    let (encapsulation, reallyme_export) = reallyme
        .hpke_setup_sender_and_export(
            CIPHERSUITE.hpke_config(),
            &libcrux_keypair.public,
            info,
            exporter_context,
            64,
        )
        .expect("ReallyMe HPKE sender export should succeed");
    let libcrux_export = libcrux
        .hpke_setup_receiver_and_export(
            CIPHERSUITE.hpke_config(),
            &encapsulation,
            &libcrux_keypair.private,
            info,
            exporter_context,
            64,
        )
        .expect("libcrux HPKE receiver export should succeed");
    assert_eq!(&*reallyme_export, &*libcrux_export);
}

#[cfg(feature = "targeted-messages-draft")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AadBuildError {}

#[test]
#[cfg(feature = "targeted-messages-draft")]
fn hpke_psk_mode_round_trips_and_rejects_short_psks() {
    use openmls_traits::crypto::HpkeSealPskResolvedAadError;

    let crypto = CryptoProvider;
    let keypair = crypto
        .derive_hpke_keypair(CIPHERSUITE.hpke_config(), b"targeted-message-key-material")
        .expect("valid key derivation should succeed");
    let psk = [0x42; 32];
    let psk_id = b"reallyme-targeted-message-psk";
    let plaintext = b"targeted message payload";
    let ciphertext = crypto
        .hpke_seal_psk_resolved_aad(
            CIPHERSUITE.hpke_config(),
            &keypair.public,
            b"targeted-message-info",
            plaintext,
            &psk,
            psk_id,
            |kem_output| Ok::<Vec<u8>, AadBuildError>(kem_output.to_vec()),
        )
        .expect("valid PSK-mode encryption should succeed");
    assert_eq!(
        crypto
            .hpke_open_psk(
                CIPHERSUITE.hpke_config(),
                &ciphertext,
                &keypair.private,
                b"targeted-message-info",
                ciphertext.kem_output.as_slice(),
                &psk,
                psk_id,
            )
            .expect("valid PSK-mode decryption should succeed"),
        plaintext
    );

    let short_psk = [0x24; 31];
    let result = crypto.hpke_seal_psk_resolved_aad(
        CIPHERSUITE.hpke_config(),
        &keypair.public,
        b"targeted-message-info",
        plaintext,
        &short_psk,
        psk_id,
        |kem_output| Ok::<Vec<u8>, AadBuildError>(kem_output.to_vec()),
    );
    assert!(matches!(
        result,
        Err(HpkeSealPskResolvedAadError::CryptoError(
            CryptoError::SenderSetupError
        ))
    ));
}

#[test]
fn hpke_rejects_malformed_keys_ciphertexts_and_oversized_exports() {
    let crypto = CryptoProvider;
    let first = crypto
        .derive_hpke_keypair(CIPHERSUITE.hpke_config(), b"ikm")
        .expect("deterministic key derivation should succeed");
    let second = crypto
        .derive_hpke_keypair(CIPHERSUITE.hpke_config(), b"ikm")
        .expect("repeated deterministic key derivation should succeed");
    assert_eq!(first.public, second.public);
    assert_eq!(&*first.private, &*second.private);
    assert_eq!(
        crypto.hpke_seal(CIPHERSUITE.hpke_config(), &[0u8; 31], &[], &[], b"payload"),
        Err(CryptoError::InvalidPublicKey)
    );
    let keypair = crypto
        .derive_hpke_keypair(CIPHERSUITE.hpke_config(), b"valid-key-material")
        .expect("valid key derivation should succeed");
    let (encapsulation, _) = crypto
        .hpke_setup_sender_and_export(CIPHERSUITE.hpke_config(), &keypair.public, &[], &[], 32)
        .expect("valid sender export should succeed");
    assert!(matches!(
        crypto.hpke_setup_receiver_and_export(
            CIPHERSUITE.hpke_config(),
            &encapsulation[..encapsulation
                .len()
                .checked_sub(1)
                .expect("encapsulation is non-empty")],
            &keypair.private,
            &[],
            &[],
            32,
        ),
        Err(CryptoError::InvalidLength)
    ));
    let oversized_export = usize::from(u16::MAX)
        .checked_add(1)
        .expect("u16 maximum plus one fits in usize");
    assert!(matches!(
        crypto.hpke_setup_receiver_and_export(
            CIPHERSUITE.hpke_config(),
            &encapsulation,
            &keypair.private,
            &[],
            &[],
            oversized_export,
        ),
        Err(CryptoError::ExporterError)
    ));
}

#[test]
fn randomness_supports_fixed_and_dynamic_requests() {
    let crypto = CryptoProvider;
    let fixed = crypto
        .random_array::<32>()
        .expect("fixed random output should succeed");
    let dynamic = crypto
        .random_vec(32)
        .expect("dynamic random output should succeed");
    assert_eq!(fixed.len(), 32);
    assert_eq!(dynamic.len(), 32);
    assert_ne!(fixed.as_slice(), dynamic.as_slice());
}
