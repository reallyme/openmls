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
    types::{
        AeadType, Ciphersuite, CryptoError, HashType, HpkeAeadType, HpkeKdfType, HpkeKemType,
        SignatureScheme,
    },
};
use reallyme_crypto::hpke::{
    derive_keypair_from_ikm_raw, open_base_raw, seal_base_derand_raw, HpkeAeadId,
    HpkeDerandSealRequest, HpkeKdfId, HpkeKemId, HpkeOpenRequest, HpkeSuite, HPKE_AEAD_NONCE_LEN,
};
use reallyme_crypto::{
    ml_dsa_87::generate_ml_dsa_87_keypair_from_seed,
    ml_kem_1024::generate_ml_kem_1024_keypair_from_seed,
};
use tls_codec::{Deserialize as _, Serialize as _};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const PURE_MLKEM1024_P384_SUITE: Ciphersuite = Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384;
const CNSA_MLKEM1024_MLDSA87_SUITE: Ciphersuite =
    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;
const HYBRID_MLKEM1024_P384_SUITE: Ciphersuite =
    Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384;
const HPKE_MLKEM1024_HKDF_SHA384_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem1024,
    HpkeKdfId::HkdfSha384,
    HpkeAeadId::Aes256Gcm,
);
const HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem1024P384,
    HpkeKdfId::HkdfSha384,
    HpkeAeadId::Aes256Gcm,
);

fn assert_private_keys_match(left: &[u8], right: &[u8]) {
    let crypto = CryptoProvider;
    let left_digest = crypto
        .hash(HashType::Sha2_256, left)
        .expect("hashing a private-key test value should succeed");
    let right_digest = crypto
        .hash(HashType::Sha2_256, right)
        .expect("hashing a private-key test value should succeed");

    // Comparing digests keeps a future non-deterministic test failure from
    // printing raw private keys through assert_eq!'s Debug output.
    assert_eq!(left_digest, right_digest);
}

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
fn official_hpke_pq_vectors_cover_production_mlkem1024_profiles() {
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
fn hpke_freshness_and_bound_input_tampering_fail_closed_for_new_suites() {
    let crypto = CryptoProvider;
    let info = b"reallyme-pq-hpke-info";
    let aad = b"reallyme-pq-hpke-aad";
    let plaintext = b"reallyme-pq-hpke-payload";

    for ciphersuite in [
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

#[cfg(feature = "targeted-messages-draft")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AadBuildError {}

#[test]
#[cfg(feature = "targeted-messages-draft")]
fn hpke_psk_mode_round_trips_and_rejects_short_psks() {
    use openmls_traits::crypto::HpkeSealPskResolvedAadError;

    let crypto = CryptoProvider;
    let keypair = crypto
        .derive_hpke_keypair(
            CIPHERSUITE.hpke_config(),
            b"targeted-message-key-derivation-material",
        )
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
    let deterministic_ikm = b"malformed-input-test-key-derivation-material";
    let first = crypto
        .derive_hpke_keypair(CIPHERSUITE.hpke_config(), deterministic_ikm)
        .expect("deterministic key derivation should succeed");
    let second = crypto
        .derive_hpke_keypair(CIPHERSUITE.hpke_config(), deterministic_ikm)
        .expect("repeated deterministic key derivation should succeed");
    assert_eq!(first.public, second.public);
    assert_private_keys_match(&first.private, &second.private);
    assert_eq!(
        crypto.hpke_seal(CIPHERSUITE.hpke_config(), &[0u8; 31], &[], &[], b"payload"),
        Err(CryptoError::InvalidPublicKey)
    );
    let keypair = crypto
        .derive_hpke_keypair(
            CIPHERSUITE.hpke_config(),
            b"valid-malformed-input-test-key-material",
        )
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
    let maximum_hkdf_sha256_export = 32_usize
        .checked_mul(255)
        .expect("RFC 9180 HKDF-SHA256 exporter bound fits in usize");
    let (maximum_encapsulation, maximum_sender_export) = crypto
        .hpke_setup_sender_and_export(
            CIPHERSUITE.hpke_config(),
            &keypair.public,
            &[],
            &[],
            maximum_hkdf_sha256_export,
        )
        .expect("the exact RFC 9180 HKDF-SHA256 exporter bound should succeed");
    let maximum_receiver_export = crypto
        .hpke_setup_receiver_and_export(
            CIPHERSUITE.hpke_config(),
            &maximum_encapsulation,
            &keypair.private,
            &[],
            &[],
            maximum_hkdf_sha256_export,
        )
        .expect("the receiver should accept the exact RFC 9180 exporter bound");
    assert_eq!(maximum_sender_export.len(), maximum_hkdf_sha256_export);
    assert_private_keys_match(&maximum_sender_export, &maximum_receiver_export);
    let oversized_hkdf_sha256_export = maximum_hkdf_sha256_export
        .checked_add(1)
        .expect("RFC 9180 HKDF-SHA256 exporter bound plus one fits in usize");
    assert!(matches!(
        crypto.hpke_setup_sender_and_export(
            CIPHERSUITE.hpke_config(),
            &keypair.public,
            &[],
            &[],
            oversized_hkdf_sha256_export,
        ),
        Err(CryptoError::ExporterError)
    ));
    assert!(matches!(
        crypto.hpke_setup_receiver_and_export(
            CIPHERSUITE.hpke_config(),
            &encapsulation,
            &keypair.private,
            &[],
            &[],
            oversized_hkdf_sha256_export,
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
