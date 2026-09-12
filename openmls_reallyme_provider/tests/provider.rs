// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC
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
    derive_keypair_from_ikm_raw, open_base_raw, seal_base_derand_raw, HpkeDerandSealRequest,
    HpkeOpenRequest, HpkeSuite, HPKE_AEAD_NONCE_LEN, HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM,
    HPKE_MLKEM1024_HKDF_SHA384_AES256GCM, HPKE_MLKEM768_HKDF_SHA384_AES256GCM,
    HPKE_XWING_HKDF_SHA384_AES256GCM,
};
use reallyme_crypto::{
    ml_dsa_87::generate_ml_dsa_87_keypair_from_seed,
    ml_kem_1024::generate_ml_kem_1024_keypair_from_seed,
};
use tls_codec::{Deserialize as _, Serialize as _};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const XWING_AES256_ED25519_SUITE: Ciphersuite =
    Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519;
const MLKEM768_MLDSA65_SUITE: Ciphersuite = Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65;
const PURE_MLKEM1024_P384_SUITE: Ciphersuite = Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384;
const CNSA_MLKEM1024_MLDSA87_SUITE: Ciphersuite =
    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;
const HYBRID_MLKEM1024_P384_SUITE: Ciphersuite =
    Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384;
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

#[path = "provider/confusion_and_interop.rs"]
mod confusion_and_interop;
#[path = "provider/hpke_boundaries.rs"]
mod hpke_boundaries;
#[path = "provider/hpke_vectors.rs"]
mod hpke_vectors;
#[path = "provider/known_answers.rs"]
mod known_answers;
#[path = "provider/primitives.rs"]
mod primitives;
