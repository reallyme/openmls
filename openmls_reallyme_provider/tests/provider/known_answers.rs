use super::*;

#[test]
fn external_known_answers_cover_provider_primitives() {
    let crypto = CryptoProvider;

    // NIST SP 800-38D AES-256-GCM, all-zero key/IV/plaintext. Keeping the
    // exact ciphertext and tag at the OpenMLS trait boundary catches routing,
    // key-size, nonce-size, and tag-concatenation regressions together.
    let aes_ciphertext = crypto
        .aead_encrypt(AeadType::Aes256Gcm, &[0u8; 32], &[0u8; 16], &[0u8; 12], &[])
        .expect("NIST AES-256-GCM known answer should encrypt");
    assert_eq!(
        hex::encode(aes_ciphertext),
        "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
    );

    // NIST ACVP ECDSA sigVer 1.0 tcId 256 (P-384/SHA2-384). The SEC1 point
    // and DER signature are constructed directly from ACVP qx/qy and r/s;
    // this intentionally does not reuse the production encoders.
    let p384_message = hex::decode(concat!(
        "8b7ae2c9b43b3150f3da84628b155b1c6d6980dea90d21c34768e0cf71fe6c4",
        "e75fca4b297440b43a0b40d11c55e92b13691e1cd3d8165302c7a0ec07ed20400",
        "ec4ac01dc692ad4e37bd600f3d4d3e55285ea275ff5898361a6b444493430001",
        "c34a5f03b4ba0fd906e026d5b8809b70bfa1037fd3c74b4b4e75d8d66bb32f5d"
    ))
    .expect("fixed ACVP message must decode");
    let p384_public = hex::decode(concat!(
        "04",
        "35178b13894cf9a62345989b5e62297e31d2cc085f25791866c7d66056f96212",
        "ef78b92b8442e76a8ba34ada651a1c38",
        "50d2605c29e3c4d9b0158d5ac178b51acac435d73e671f09bba7e0f7c741e502",
        "b34fe348083ddb22955cf4e2bec92cd1"
    ))
    .expect("fixed ACVP public key must decode");
    let p384_signature = hex::decode(concat!(
        "3064",
        "0230",
        "51c098f7285711bb5b17427482f58d2633c530d6ffbe1d8efb117a30f59e3072",
        "d4eb3fdb8db5372c2b4d83c2d6051d58",
        "0230",
        "1481a2669efee8546625adb6703f8c8946343473cb69d54dbc86ac689ed71e03f",
        "47b88e8d49b5c02b92730b7aa44e80e"
    ))
    .expect("fixed ACVP signature must decode");
    crypto
        .verify_signature(
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            &p384_message,
            &p384_public,
            &p384_signature,
        )
        .expect("NIST P-384 known answer should verify");

    // NIST ACVP ML-DSA keyGen tcId 51. Comparing a SHA-256 commitment keeps
    // the 2,592-byte public key out of this source file while still pinning
    // every output byte. The resulting seed/public representation is then
    // exercised through the OpenMLS sign and verify boundary.
    let ml_dsa_seed: [u8; 32] =
        hex::decode("f7052fbb921759cd8716773ba6355630121d6927899fdda5768e2bc240fccb7b")
            .expect("fixed ACVP ML-DSA seed must decode")
            .try_into()
            .expect("ACVP ML-DSA seed has the required length");
    let (ml_dsa_public, ml_dsa_private) = generate_ml_dsa_87_keypair_from_seed(&ml_dsa_seed)
        .expect("NIST ML-DSA keygen known answer should derive");
    assert_eq!(
        hex::encode(
            crypto
                .hash(HashType::Sha2_256, &ml_dsa_public)
                .expect("ML-DSA public-key commitment should hash")
        ),
        "40298270777d3306d2fcb6b4691d7a7ab799cd1069eea88f843cf0ec26d4b01f"
    );
    let ml_dsa_message = b"provider-boundary ML-DSA known-key check";
    let ml_dsa_signature = crypto
        .sign(SignatureScheme::MLDSA87, ml_dsa_message, &ml_dsa_private)
        .expect("provider should sign with the NIST-derived seed");
    crypto
        .verify_signature(
            SignatureScheme::MLDSA87,
            ml_dsa_message,
            &ml_dsa_public,
            &ml_dsa_signature,
        )
        .expect("provider should verify the NIST-derived ML-DSA key");

    // NIST ACVP ML-KEM keyGen tcId 51. HPKE DeriveKeyPair has additional
    // draft labeling, so this component KAT intentionally checks the exact
    // ML-KEM primitive used beneath both ML-KEM-1024 HPKE profiles.
    let ml_kem_seed: [u8; 64] = hex::decode(concat!(
        "f3a706faf090c03db506863ab0b20bd8a1627956318e88c67eb875e8e7266009",
        "35d2bc43dd1cc879f765bf2a0c5e297889dde910e57e2bb0eae417b90ab7a275"
    ))
    .expect("fixed ACVP ML-KEM seed must decode")
    .try_into()
    .expect("ACVP ML-KEM seed has the required length");
    let (ml_kem_public, _ml_kem_private) = generate_ml_kem_1024_keypair_from_seed(&ml_kem_seed)
        .expect("NIST ML-KEM keygen known answer should derive");
    assert_eq!(
        hex::encode(
            crypto
                .hash(HashType::Sha2_256, &ml_kem_public)
                .expect("ML-KEM public-key commitment should hash")
        ),
        "b78619e4fceeeb86dee3fedb945eca6da61dae312771ef8fa871951d391bd7b6"
    );
}

#[test]
fn official_hpke_pq_vectors_cover_production_mlkem_profiles() {
    // Source: hpke-pq test-vectors.json at commit
    // 11b5b9541e9976fc9ce25902011d20dacc089066. The reviewed file's SHA-256 is
    // 35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c.
    // Draft-06 selects the HKDF-SHA384 cases below without modifying their
    // HPKE composition, so these are independent exact vectors for both
    // production ML-KEM-1024 profiles rather than component-only evidence.
    let info = hex::decode(
        "34663634363532303666366532303631323034373732363536333639363136653230353537323665",
    )
    .expect("fixed HPKE-PQ info must decode");
    let aad = hex::decode("436f756e742d30").expect("fixed HPKE-PQ AAD must decode");
    let plaintext = hex::decode(concat!(
        "3432363536313735373437393230363937333230373437323735373436383263",
        "3230373437323735373436383230363236353631373537343739"
    ))
    .expect("fixed HPKE-PQ plaintext must decode");

    let crypto = CryptoProvider;
    let digest = |bytes: &[u8]| {
        hex::encode(
            crypto
                .hash(HashType::Sha2_256, bytes)
                .expect("HPKE-PQ vector commitment should hash"),
        )
    };
    // Appendix A.2 uses the same ML-KEM-768 KEM with an AES-128 outer HPKE
    // profile. Its KEM key and encapsulation commitments remain independent
    // evidence for the MLS HKDF-SHA384/AES-256 composition used here.
    let mlkem768_recipient_ikm = hex::decode(concat!(
        "a60b35f174ce9ac7a4ff5b9f81e38125b03506ecbd56a3a55c31ece0f5907052",
        "0729773a61a499d5137daaef824b493848b6e4dd332a815ff19aa9f58a381eb8"
    ))
    .expect("fixed HPKE-PQ ML-KEM-768 recipient IKM must decode");
    let mlkem768_sender_ikm =
        hex::decode("9b933cd9c9421cd58db0c5f6cea53eedbd7fae056ff95d688d8ed9a58177e76b")
            .expect("fixed HPKE-PQ ML-KEM-768 sender IKM must decode");
    let mlkem768_recipient =
        derive_keypair_from_ikm_raw(HPKE_MLKEM768_HKDF_SHA384_AES256GCM, &mlkem768_recipient_ikm)
            .expect("official ML-KEM-768 recipient derivation should succeed");
    let provider_mlkem768_recipient = crypto
        .derive_hpke_keypair(
            MLKEM768_MLDSA65_SUITE.hpke_config(),
            &mlkem768_recipient_ikm,
        )
        .expect("provider ML-KEM-768 recipient derivation should succeed");
    assert_eq!(
        provider_mlkem768_recipient.public,
        mlkem768_recipient.public_key
    );
    assert_private_keys_match(
        &provider_mlkem768_recipient.private,
        mlkem768_recipient.private_key(),
    );
    assert_eq!(
        digest(&mlkem768_recipient.public_key),
        "80aabb142999e683475598517f3bca6b9b8c8f01109ec8f861b450d2a8b9148d"
    );
    assert_eq!(
        digest(mlkem768_recipient.private_key()),
        "386aeafcaac84b3ae7227e02d6ca8a77b5b909866fe8542e5e84dd7bc14dba9b"
    );
    let mlkem768_sealed = seal_base_derand_raw(&HpkeDerandSealRequest {
        suite: HPKE_MLKEM768_HKDF_SHA384_AES256GCM,
        recipient_public_key: &mlkem768_recipient.public_key,
        encapsulation_randomness: &mlkem768_sender_ikm,
        info: &info,
        aad: &aad,
        plaintext: &plaintext,
    })
    .expect("official ML-KEM-768 encapsulation should succeed");
    assert_eq!(
        digest(&mlkem768_sealed.encapsulated_key),
        "48f93a13c1ee2be820054837dae8c60bb9fdec23347521ec8b81d0e4716a649c"
    );
    let mlkem768_opened = open_base_raw(&HpkeOpenRequest {
        suite: HPKE_MLKEM768_HKDF_SHA384_AES256GCM,
        encapsulated_key: &mlkem768_sealed.encapsulated_key,
        recipient_private_key: mlkem768_recipient.private_key(),
        info: &info,
        aad: &aad,
        ciphertext: &mlkem768_sealed.ciphertext,
    })
    .expect("MLS ML-KEM-768 profile ciphertext should open");
    assert_eq!(mlkem768_opened.plaintext.as_slice(), plaintext);

    // The standards-tracking X-Wing profile must use ReallyMe Crypto's
    // HPKE-PQ labeled DeriveKeyPair path, not the legacy compatibility
    // normalization retained for the deployed ChaCha20/SHA-256 suite.
    let xwing_recipient_ikm = b"standards-tracking X-Wing recipient IKM";
    let xwing_recipient =
        derive_keypair_from_ikm_raw(HPKE_XWING_HKDF_SHA384_AES256GCM, xwing_recipient_ikm)
            .expect("standards-tracking X-Wing recipient derivation should succeed");
    let provider_xwing_recipient = crypto
        .derive_hpke_keypair(
            XWING_AES256_ED25519_SUITE.hpke_config(),
            xwing_recipient_ikm,
        )
        .expect("provider X-Wing recipient derivation should succeed");
    assert_eq!(provider_xwing_recipient.public, xwing_recipient.public_key);
    assert_private_keys_match(
        &provider_xwing_recipient.private,
        xwing_recipient.private_key(),
    );

    let mlkem_recipient_ikm = hex::decode(concat!(
        "d6688a981deeff1d1273426af8a44aab877c50b6e8ac74b11e01a5960d97c03b",
        "ffd9634894d255c424c80c74e0930b85b9f4c60e22a3efb09f4bad4749be427b"
    ))
    .expect("fixed HPKE-PQ ML-KEM recipient IKM must decode");
    let mlkem_sender_ikm =
        hex::decode("54e68c4d0f72b94d956acf637c23570e505db5c08c0068bd136cacbc7dedda89")
            .expect("fixed HPKE-PQ ML-KEM sender IKM must decode");
    let mlkem_recipient =
        derive_keypair_from_ikm_raw(HPKE_MLKEM1024_HKDF_SHA384_AES256GCM, &mlkem_recipient_ikm)
            .expect("official ML-KEM-1024 recipient derivation should succeed");
    let provider_mlkem_recipient = crypto
        .derive_hpke_keypair(
            PURE_MLKEM1024_P384_SUITE.hpke_config(),
            &mlkem_recipient_ikm,
        )
        .expect("provider ML-KEM-1024 recipient derivation should succeed");
    assert_eq!(provider_mlkem_recipient.public, mlkem_recipient.public_key);
    assert_private_keys_match(
        &provider_mlkem_recipient.private,
        mlkem_recipient.private_key(),
    );
    assert_eq!(
        digest(&mlkem_recipient.public_key),
        "b45440fa44f6a7046ecf45d77fdd4fd9f02982defa787501ba365f0c264d9f73"
    );
    assert_eq!(
        digest(mlkem_recipient.private_key()),
        "e328f149f09f5414295528ea27cc9e17e6de6eb7647bfda19c36a828118cf05b"
    );
    let mlkem_sealed = seal_base_derand_raw(&HpkeDerandSealRequest {
        suite: HPKE_MLKEM1024_HKDF_SHA384_AES256GCM,
        recipient_public_key: &mlkem_recipient.public_key,
        encapsulation_randomness: &mlkem_sender_ikm,
        info: &info,
        aad: &aad,
        plaintext: &plaintext,
    })
    .expect("official ML-KEM-1024 encapsulation should succeed");
    assert_eq!(
        digest(&mlkem_sealed.encapsulated_key),
        "235e148aedf1e71805c8a5cb20555a45e427a0adbf5d22150531fa653287211b"
    );
    assert_eq!(
        hex::encode(&mlkem_sealed.ciphertext),
        concat!(
            "9d16979cb9ac997886c0ec51ed2c049d7ec53b369467026157ef061af23695b9",
            "96e1893afd2173c310546859e82eea9c16e0a1363bc994f2ff708e5d60089c1b",
            "233f38ce6a7fbd176744"
        )
    );

    // The hybrid vector independently covers its concatenated public key,
    // private seed, encapsulation, combiner output, and HPKE key schedule.
    let hybrid_recipient_ikm =
        hex::decode("14c036a5e3c4af452baccdcd62cf818f250607076c299636e5c8074b3c757df1")
            .expect("fixed HPKE-PQ hybrid recipient IKM must decode");
    let hybrid_sender_ikm = hex::decode(concat!(
        "a2aa5d3e682abee327d4d258e47fdf9b987efc96a15e1f11fd81413206d1ae2a",
        "b11e0d808cb65a680cf32b00eed796e02d149f3454974db3e1751cf2fc1916e0",
        "d887c307c18b28645809760d00d6191a"
    ))
    .expect("fixed HPKE-PQ hybrid sender IKM must decode");
    let hybrid_recipient = derive_keypair_from_ikm_raw(
        HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM,
        &hybrid_recipient_ikm,
    )
    .expect("official ML-KEM-1024+P-384 recipient derivation should succeed");
    let provider_hybrid_recipient = crypto
        .derive_hpke_keypair(
            HYBRID_MLKEM1024_P384_SUITE.hpke_config(),
            &hybrid_recipient_ikm,
        )
        .expect("provider ML-KEM-1024+P-384 recipient derivation should succeed");
    assert_eq!(
        provider_hybrid_recipient.public,
        hybrid_recipient.public_key
    );
    assert_private_keys_match(
        &provider_hybrid_recipient.private,
        hybrid_recipient.private_key(),
    );
    assert_eq!(
        digest(&hybrid_recipient.public_key),
        "2fa438cda8bdfa993e8286a31a3c7d90766dacd114131cd5dfecf466eab936e3"
    );
    assert_eq!(
        digest(hybrid_recipient.private_key()),
        "03f254652cbe6905cf09edf590fc6a830910bfe69534231eb46e50b8f2de9776"
    );
    let hybrid_sealed = seal_base_derand_raw(&HpkeDerandSealRequest {
        suite: HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM,
        recipient_public_key: &hybrid_recipient.public_key,
        encapsulation_randomness: &hybrid_sender_ikm,
        info: &info,
        aad: &aad,
        plaintext: &plaintext,
    })
    .expect("official ML-KEM-1024+P-384 encapsulation should succeed");
    assert_eq!(
        digest(&hybrid_sealed.encapsulated_key),
        "dca2c5ed53db453080df9de9e7d38191d10f8362fc9b47c57650c357ed99588c"
    );
    assert_eq!(
        hex::encode(&hybrid_sealed.ciphertext),
        concat!(
            "1af5c6176d191f913bb9a39ae6af2c5847d5effca2d794242de5464ef287bfd6",
            "d5f6735bab1b42b3d29a6b131a91b180b04dbf6afc395bdc35f2b8558db9c6",
            "2ce54c81872b42d222459a"
        )
    );
}
