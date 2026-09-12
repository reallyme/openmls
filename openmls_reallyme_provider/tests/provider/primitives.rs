use super::*;

#[test]
fn advertises_only_reallyme_reviewed_suites() {
    let crypto = CryptoProvider;
    assert_eq!(
        crypto.supported_ciphersuites(),
        vec![
            CIPHERSUITE,
            XWING_AES256_ED25519_SUITE,
            MLKEM768_MLDSA65_SUITE,
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
fn reviewed_suite_codepoints_and_components_are_exact() {
    let expected = [
        (
            CIPHERSUITE,
            0x004d,
            HpkeKemType::XWingKemDraft6,
            HpkeKdfType::HkdfSha256,
            HpkeAeadType::ChaCha20Poly1305,
            HashType::Sha2_256,
            AeadType::ChaCha20Poly1305,
            SignatureScheme::ED25519,
        ),
        (
            XWING_AES256_ED25519_SUITE,
            0x004e,
            HpkeKemType::XWingKemDraft6,
            HpkeKdfType::HkdfSha384,
            HpkeAeadType::AesGcm256,
            HashType::Sha2_384,
            AeadType::Aes256Gcm,
            SignatureScheme::ED25519,
        ),
        (
            MLKEM768_MLDSA65_SUITE,
            0x0051,
            HpkeKemType::MlKem768,
            HpkeKdfType::HkdfSha384,
            HpkeAeadType::AesGcm256,
            HashType::Sha2_384,
            AeadType::Aes256Gcm,
            SignatureScheme::MLDSA65,
        ),
        (
            PURE_MLKEM1024_P384_SUITE,
            0x0042,
            HpkeKemType::MlKem1024,
            HpkeKdfType::HkdfSha384,
            HpkeAeadType::AesGcm256,
            HashType::Sha2_384,
            AeadType::Aes256Gcm,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
        ),
        (
            CNSA_MLKEM1024_MLDSA87_SUITE,
            0x0907,
            HpkeKemType::MlKem1024,
            HpkeKdfType::HkdfSha384,
            HpkeAeadType::AesGcm256,
            HashType::Sha2_384,
            AeadType::Aes256Gcm,
            SignatureScheme::MLDSA87,
        ),
        (
            HYBRID_MLKEM1024_P384_SUITE,
            0xf043,
            HpkeKemType::MlKem1024P384,
            HpkeKdfType::HkdfSha384,
            HpkeAeadType::AesGcm256,
            HashType::Sha2_384,
            AeadType::Aes256Gcm,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
        ),
    ];

    for (suite, codepoint, kem, kdf, hpke_aead, hash, aead, signature) in expected {
        assert_eq!(u16::from(suite), codepoint);
        assert_eq!(Ciphersuite::try_from(codepoint), Ok(suite));
        let wire = suite
            .tls_serialize_detached()
            .expect("reviewed ciphersuite should serialize");
        assert_eq!(wire, codepoint.to_be_bytes());
        assert_eq!(
            Ciphersuite::tls_deserialize_exact(&wire)
                .expect("reviewed ciphersuite should deserialize"),
            suite
        );
        assert_eq!(suite.hpke_kem_algorithm(), kem);
        assert_eq!(suite.hpke_kdf_algorithm(), kdf);
        assert_eq!(suite.hpke_aead_algorithm(), hpke_aead);
        assert_eq!(suite.hash_algorithm(), hash);
        assert_eq!(suite.aead_algorithm(), aead);
        assert_eq!(suite.signature_algorithm(), signature);
    }
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
    let mut aes_ciphertext = crypto
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
    if let Some(last) = aes_ciphertext.last_mut() {
        *last ^= 0x80;
    }
    assert_eq!(
        crypto.aead_decrypt(
            AeadType::Aes256Gcm,
            &aes_key,
            &aes_ciphertext,
            &aes_nonce,
            aad
        ),
        Err(CryptoError::AeadDecryptionError)
    );
    assert_eq!(
        crypto.aead_encrypt(AeadType::Aes256Gcm, &[0u8; 31], plaintext, &aes_nonce, aad),
        Err(CryptoError::InvalidLength)
    );
    assert_eq!(
        crypto.aead_encrypt(AeadType::Aes256Gcm, &aes_key, plaintext, &[0u8; 11], aad),
        Err(CryptoError::InvalidLength)
    );
    assert_eq!(
        crypto.aead_decrypt(AeadType::Aes256Gcm, &aes_key, &[0u8; 15], &aes_nonce, aad),
        Err(CryptoError::InvalidLength)
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

    let (ml_dsa_65_secret, ml_dsa_65_public) = crypto
        .signature_key_gen(SignatureScheme::MLDSA65)
        .expect("valid ReallyMe ML-DSA-65 key generation should succeed");
    let ml_dsa_65_signature = crypto
        .sign(SignatureScheme::MLDSA65, plaintext, &ml_dsa_65_secret)
        .expect("valid ReallyMe ML-DSA-65 signing should succeed");
    crypto
        .verify_signature(
            SignatureScheme::MLDSA65,
            plaintext,
            &ml_dsa_65_public,
            &ml_dsa_65_signature,
        )
        .expect("valid ReallyMe ML-DSA-65 verification should succeed");
    assert_eq!(
        crypto.verify_signature(
            SignatureScheme::MLDSA65,
            b"tampered",
            &ml_dsa_65_public,
            &ml_dsa_65_signature,
        ),
        Err(CryptoError::InvalidSignature)
    );
    assert_eq!(
        crypto.verify_signature(
            SignatureScheme::MLDSA65,
            plaintext,
            &[0u8; 1],
            &ml_dsa_65_signature,
        ),
        Err(CryptoError::InvalidPublicKey)
    );
    assert_eq!(
        crypto.sign(SignatureScheme::MLDSA65, plaintext, &[0u8; 31]),
        Err(CryptoError::InvalidLength)
    );
    assert_eq!(
        crypto.verify_signature(
            SignatureScheme::MLDSA65,
            plaintext,
            &ml_dsa_65_public,
            &[0u8; 3_308],
        ),
        Err(CryptoError::InvalidSignature)
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
    assert_eq!(
        crypto.verify_signature(
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            b"tampered",
            &p384_public,
            &p384_signature,
        ),
        Err(CryptoError::InvalidSignature)
    );
    assert_eq!(
        crypto.verify_signature(
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            plaintext,
            &[0u8; 96],
            &p384_signature,
        ),
        Err(CryptoError::InvalidPublicKey)
    );

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
    assert_eq!(
        crypto.verify_signature(
            SignatureScheme::MLDSA87,
            b"tampered",
            &ml_dsa_public,
            &ml_dsa_signature,
        ),
        Err(CryptoError::InvalidSignature)
    );
    assert_eq!(
        crypto.verify_signature(
            SignatureScheme::MLDSA87,
            plaintext,
            &[0u8; 1],
            &ml_dsa_signature,
        ),
        Err(CryptoError::InvalidPublicKey)
    );
}
