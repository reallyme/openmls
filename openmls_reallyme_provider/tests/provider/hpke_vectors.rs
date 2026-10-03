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
    const IKM: &[u8] = b"fixed OpenMLS vector IKM 32 byte";
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
            "8287b94d850bd91a6fdd2a8dd03bd3895609ebe630f299ef8dd3f2982571b68a",
            "cd68e139d4d8e8699d7e2512dbe3985b3cc6d9898b4936b2265f80a3d2dd468b",
            "b218f3225439e549a0f998169d22c2cbaa4af971be4880142a0fd4465a5b5d6b",
            "db3ff04c7e7ee152a04cfc41242fefdf7f2eeffc1ade25aecfc324edbbc4db0c",
        ],
    );
    assert_pinned_reallyme_vector(
        HPKE_XWING_HKDF_SHA384_AES256GCM,
        IKM,
        INFO,
        AAD,
        PLAINTEXT,
        [
            "62a841c9c229eb7c712e08a05a5fd84697dc7591cfb45837a25a2ac5e8e2b3e3",
            "78be12731c7fad7f1f381e76f1887b299232d0927fa0409676ea2ba98af909c6",
            "87b382a15988fa58f905a25c1b62b8a1171723ddcd37595eaae4a487d5f6bd37",
            "8cb99f1878ed6d28a1f54add083fbb665c1f8218d8eeea2ee96e0b8334925c0f",
        ],
    );
    assert_pinned_reallyme_vector(
        HPKE_MLKEM1024_HKDF_SHA384_AES256GCM,
        IKM,
        INFO,
        AAD,
        PLAINTEXT,
        [
            "42cd016b92a86bf647f36b64c4d8bf21ffbd7946a369305ada781721ba1d926c",
            "771b3ed5ed7a30203be4a190c867670f45aa71c42ae004a85dc5a841ee7806bd",
            "6520978ee968f8272e4e3323b437455a0c588d12e0fa45fcc9ce5209388a4fcc",
            "5b4f2b8dd43e70387918e304bbe840f8cbbeee1a5e8cade6b322440bcf396e4a",
        ],
    );
    assert_pinned_reallyme_vector(
        HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM,
        IKM,
        INFO,
        AAD,
        PLAINTEXT,
        [
            "866f1922f737e20c7aba400c45ce346356df926683efd82d20395e7752181465",
            "6d5419b692a5d4056e677d33fc3ab28761091056f982024c4b16c743bf205101",
            "396dc60ba04e1b80e67fd20b0cb476fb55bb1cd0de3f29fc8145963e6b489232",
            "418aeb8d6d8b8bebc454f88eb092759398630938cdd37c21c49dabe96eebea33",
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
