use super::*;

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
fn hpke_large_mls_contexts_roundtrip_and_bind_every_byte() {
    // Inline ML-DSA ratchet trees exceed 64 KiB even for modest groups. HKDF
    // accepts that complete MLS context; prehashing it here would change the wire
    // protocol. Cover both sides of the former backend limit and a larger tree.
    let crypto = CryptoProvider;
    for suite in crypto.supported_ciphersuites() {
        let keypair = crypto
            .derive_hpke_keypair(suite.hpke_config(), &[0x42; 32])
            .expect("fixture key derivation should succeed");
        for info_length in [65_530, 65_531, 131_072] {
            let mut info = vec![0x42; info_length];
            let ciphertext = crypto
                .hpke_seal(suite.hpke_config(), &keypair.public, &info, &[], b"fixture")
                .expect("large MLS contexts should seal");
            assert_eq!(
                crypto
                    .hpke_open(
                        suite.hpke_config(),
                        &ciphertext,
                        &keypair.private,
                        &info,
                        &[]
                    )
                    .expect("large MLS contexts should open"),
                b"fixture"
            );
            let (encapsulation, sender_export) = crypto
                .hpke_setup_sender_and_export(
                    suite.hpke_config(),
                    &keypair.public,
                    &info,
                    &info,
                    32,
                )
                .expect("large contexts should support sender export");
            let receiver_export = crypto
                .hpke_setup_receiver_and_export(
                    suite.hpke_config(),
                    &encapsulation,
                    &keypair.private,
                    &info,
                    &info,
                    32,
                )
                .expect("large contexts should support receiver export");
            assert_private_keys_match(&sender_export, &receiver_export);
            let mut changed_context = info.clone();
            *changed_context.last_mut().expect("fixture is nonempty") ^= 1;
            // A matching sender/receiver result alone could hide symmetric
            // truncation. Bind each context independently, including its tail.
            for (setup_info, exporter_context) in [
                (changed_context.as_slice(), info.as_slice()),
                (info.as_slice(), changed_context.as_slice()),
            ] {
                let changed_export = crypto
                    .hpke_setup_receiver_and_export(
                        suite.hpke_config(),
                        &encapsulation,
                        &keypair.private,
                        setup_info,
                        exporter_context,
                        32,
                    )
                    .expect("changed context still permits key derivation");
                let expected: &[u8] = &sender_export;
                let changed: &[u8] = &changed_export;
                assert!(expected != changed);
            }
            *info.last_mut().expect("fixture is nonempty") ^= 1;
            assert!(crypto
                .hpke_open(
                    suite.hpke_config(),
                    &ciphertext,
                    &keypair.private,
                    &info,
                    &[]
                )
                .is_err());
        }
    }
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
