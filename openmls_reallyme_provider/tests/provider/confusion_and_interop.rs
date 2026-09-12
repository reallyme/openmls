use super::*;

#[test]
fn cross_suite_key_and_signature_confusion_fails_closed() {
    let crypto = CryptoProvider;
    let pure_keypair = crypto
        .derive_hpke_keypair(
            PURE_MLKEM1024_P384_SUITE.hpke_config(),
            b"pure ML-KEM cross-suite key material",
        )
        .expect("pure ML-KEM key derivation should succeed");
    let hybrid_keypair = crypto
        .derive_hpke_keypair(
            HYBRID_MLKEM1024_P384_SUITE.hpke_config(),
            b"hybrid ML-KEM cross-suite key material",
        )
        .expect("hybrid ML-KEM key derivation should succeed");

    assert!(crypto
        .hpke_seal(
            HYBRID_MLKEM1024_P384_SUITE.hpke_config(),
            &pure_keypair.public,
            b"cross-suite info",
            b"cross-suite aad",
            b"cross-suite payload",
        )
        .is_err());
    assert!(crypto
        .hpke_seal(
            PURE_MLKEM1024_P384_SUITE.hpke_config(),
            &hybrid_keypair.public,
            b"cross-suite info",
            b"cross-suite aad",
            b"cross-suite payload",
        )
        .is_err());

    let message = b"signature schemes must not be interchangeable";
    let (p384_secret, p384_public) = crypto
        .signature_key_gen(SignatureScheme::ECDSA_SECP384R1_SHA384)
        .expect("P-384 key generation should succeed");
    let p384_signature = crypto
        .sign(
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            message,
            &p384_secret,
        )
        .expect("P-384 signing should succeed");
    assert!(crypto
        .verify_signature(
            SignatureScheme::MLDSA87,
            message,
            &p384_public,
            &p384_signature,
        )
        .is_err());

    let (ml_dsa_secret, ml_dsa_public) = crypto
        .signature_key_gen(SignatureScheme::MLDSA87)
        .expect("ML-DSA-87 key generation should succeed");
    let ml_dsa_signature = crypto
        .sign(SignatureScheme::MLDSA87, message, &ml_dsa_secret)
        .expect("ML-DSA-87 signing should succeed");
    assert!(crypto
        .verify_signature(
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            message,
            &ml_dsa_public,
            &ml_dsa_signature,
        )
        .is_err());

    let (ml_dsa_65_secret, ml_dsa_65_public) = crypto
        .signature_key_gen(SignatureScheme::MLDSA65)
        .expect("ML-DSA-65 key generation should succeed");
    let ml_dsa_65_signature = crypto
        .sign(SignatureScheme::MLDSA65, message, &ml_dsa_65_secret)
        .expect("ML-DSA-65 signing should succeed");
    assert!(crypto
        .verify_signature(
            SignatureScheme::MLDSA87,
            message,
            &ml_dsa_65_public,
            &ml_dsa_65_signature,
        )
        .is_err());
    assert!(crypto
        .verify_signature(
            SignatureScheme::MLDSA65,
            message,
            &ml_dsa_public,
            &ml_dsa_signature,
        )
        .is_err());
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
    assert_private_keys_match(&reallyme_keypair.private, &libcrux_keypair.private);

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
