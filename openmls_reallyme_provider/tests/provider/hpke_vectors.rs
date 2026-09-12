use super::*;

#[test]
fn reallyme_hpke_round_trips_all_current_draft_suites() {
    let crypto = CryptoProvider;
    for ciphersuite in [
        XWING_AES256_ED25519_SUITE,
        MLKEM768_MLDSA65_SUITE,
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
fn hpke_freshness_and_bound_input_tampering_fail_closed_for_current_draft_suites() {
    let crypto = CryptoProvider;
    let info = b"reallyme-pq-hpke-info";
    let aad = b"reallyme-pq-hpke-aad";
    let plaintext = b"reallyme-pq-hpke-payload";

    for ciphersuite in [
        XWING_AES256_ED25519_SUITE,
        MLKEM768_MLDSA65_SUITE,
        PURE_MLKEM1024_P384_SUITE,
        CNSA_MLKEM1024_MLDSA87_SUITE,
        HYBRID_MLKEM1024_P384_SUITE,
    ] {
        let keypair = crypto
            .derive_hpke_keypair(
                ciphersuite.hpke_config(),
                b"reallyme-openmls-mlkem1024-tamper-key-material",
            )
            .expect("valid deterministic key derivation should succeed");
        let first = crypto
            .hpke_seal(
                ciphersuite.hpke_config(),
                &keypair.public,
                info,
                aad,
                plaintext,
            )
            .expect("first seal should succeed");
        let second = crypto
            .hpke_seal(
                ciphersuite.hpke_config(),
                &keypair.public,
                info,
                aad,
                plaintext,
            )
            .expect("second seal should succeed");
        assert_ne!(first.kem_output, second.kem_output);
        assert_ne!(first.ciphertext, second.ciphertext);

        let mut changed_encapsulation = first.clone();
        let mut changed_encapsulation_bytes: Vec<u8> = changed_encapsulation.kem_output.into();
        if let Some(first_byte) = changed_encapsulation_bytes.first_mut() {
            *first_byte ^= 0x80;
        }
        changed_encapsulation.kem_output = changed_encapsulation_bytes.into();
        assert!(crypto
            .hpke_open(
                ciphersuite.hpke_config(),
                &changed_encapsulation,
                &keypair.private,
                info,
                aad,
            )
            .is_err());

        let mut changed_ciphertext = first.clone();
        let mut changed_ciphertext_bytes: Vec<u8> = changed_ciphertext.ciphertext.into();
        if let Some(last_byte) = changed_ciphertext_bytes.last_mut() {
            *last_byte ^= 0x80;
        }
        changed_ciphertext.ciphertext = changed_ciphertext_bytes.into();
        assert_eq!(
            crypto.hpke_open(
                ciphersuite.hpke_config(),
                &changed_ciphertext,
                &keypair.private,
                info,
                aad,
            ),
            Err(CryptoError::HpkeDecryptionError)
        );
        assert!(crypto
            .hpke_open(
                ciphersuite.hpke_config(),
                &first,
                &keypair.private,
                b"changed info",
                aad,
            )
            .is_err());
        assert_eq!(
            crypto.hpke_open(
                ciphersuite.hpke_config(),
                &first,
                &keypair.private,
                info,
                b"changed aad",
            ),
            Err(CryptoError::HpkeDecryptionError)
        );
        for invalid_ikm_length in [0, 1, 31] {
            let invalid_ikm = vec![0u8; invalid_ikm_length];
            assert!(matches!(
                crypto.derive_hpke_keypair(ciphersuite.hpke_config(), &invalid_ikm),
                Err(CryptoError::InvalidLength)
            ));
        }
    }
}

#[test]
fn draft_hpke_profiles_match_pinned_upgrade_regression_digests() {
    const IKM: &[u8] = b"fixed OpenMLS vector IKM";
    const INFO: &[u8] = b"fixed OpenMLS vector info";
    const AAD: &[u8] = b"fixed OpenMLS vector aad";
    const PLAINTEXT: &[u8] = b"fixed OpenMLS vector plaintext";

    assert_eq!(HPKE_AEAD_NONCE_LEN, 12);
    assert_pinned_reallyme_vector(
        HPKE_MLKEM768_HKDF_SHA384_AES256GCM,
        IKM,
        INFO,
        AAD,
        PLAINTEXT,
        [
            "150b2521121e7cea0c60affa21c60253d2f9eaee42a782c5f0c3906a7def4f7a",
            "59eec055d5e9924168829e75ed1f3afe84e2b4b40efd7a3ac1a3615f7a7af888",
            "800cf60d0deaae0a67e6c782eef28591fe875c4314f813368502a2197d9e1cde",
            "944a55bf91e7369dd43d1a5bbe3cc5af2cb2f73d85a53c9992c4bc5815141d9b",
        ],
    );
    assert_pinned_reallyme_vector(
        HPKE_XWING_HKDF_SHA384_AES256GCM,
        IKM,
        INFO,
        AAD,
        PLAINTEXT,
        [
            "b1aa872314ed253842d6ab867bda90e08e327b8fd0d0dd3239b26b242a39a2ec",
            "8901fc0095e32d6da238f6fdeebedefae49096e960b868218ddd4d772298d663",
            "c52c10d6bb3a5536a9d1846c57a18ebb8066a7018adbfd90d1553cbb44881a8c",
            "ff8c9299767334d8efb08e546f8a3033a047adb695c94cccd87e6a5d825cf73d",
        ],
    );
    assert_pinned_reallyme_vector(
        HPKE_MLKEM1024_HKDF_SHA384_AES256GCM,
        IKM,
        INFO,
        AAD,
        PLAINTEXT,
        [
            "27e21affa9959388fe4300b95892932d409aa0ed91a77f28c5798a9ec817b3ff",
            "69b6db36672ca2caab5035ff1e485b50bfcf13d0dab70ce69aa57c7e3c95bd7d",
            "38c49f420842d1d954b2ba0a98e39f3ae8a9779107a2fc1794ccf68be4ae5664",
            "0d485b39728b66256a6e1763651a40e4c243a431e39233783e3637ccaca5e180",
        ],
    );
    assert_pinned_reallyme_vector(
        HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM,
        IKM,
        INFO,
        AAD,
        PLAINTEXT,
        [
            "7f5e6d8b61d83c3455de618e07421606fcb814fa421a167a4ea6c897ca8b511c",
            "ccbac6d612ca500e0f5dae67d02055a573ea11a5c813c9fd4a44fdbc2c1be5cb",
            "388c1c3e7dcf61441d28e69e477affb64531a58a63125aeb650779844ec8f8e9",
            "d33506d03cc985ab47d521edc71ae7cace2ca63e5a22e68c232519b1a20ca801",
        ],
    );
}

fn assert_pinned_reallyme_vector(
    suite: HpkeSuite,
    ikm: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    expected_sha256: [&str; 4],
) {
    let recipient = derive_keypair_from_ikm_raw(suite, ikm)
        .expect("deterministic recipient derivation should succeed");
    let randomness_length = suite
        .encapsulation_randomness_len()
        .expect("reviewed OpenMLS profile should expose its randomness length");
    let randomness = vec![0x39; randomness_length];
    let request = HpkeDerandSealRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: &randomness,
        info,
        aad,
        plaintext,
    };
    let sealed = seal_base_derand_raw(&request).expect("deterministic seal should succeed");

    // These are regression digests generated from the reviewed ReallyMe
    // release, not independent conformance vectors. They deliberately pin all
    // deterministic outputs without placing the private key in assertion
    // diagnostics. Official HPKE-PQ cases independently cover both exact
    // production profiles with different fixed inputs; these commitments add
    // a stable backend-upgrade drift signal for this adapter's chosen inputs.
    let crypto = CryptoProvider;
    let digest = |bytes: &[u8]| {
        hex::encode(
            crypto
                .hash(HashType::Sha2_256, bytes)
                .expect("SHA-256 regression digest should succeed"),
        )
    };
    let actual_sha256 = [
        digest(&recipient.public_key),
        digest(recipient.private_key()),
        digest(&sealed.encapsulated_key),
        digest(&sealed.ciphertext),
    ];
    assert_eq!(actual_sha256, expected_sha256);

    let opened = open_base_raw(&HpkeOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: recipient.private_key(),
        info,
        aad,
        ciphertext: &sealed.ciphertext,
    })
    .expect("deterministic vector should open");
    assert_eq!(opened.plaintext.as_slice(), plaintext);
}
