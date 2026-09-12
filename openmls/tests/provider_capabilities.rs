// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT

#![cfg(feature = "reallyme-provider")]

use openmls::prelude::*;
use openmls_reallyme_provider::{Provider, ReallyMeSuiteSigner};

fn credential(signer: &ReallyMeSuiteSigner) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(b"capability policy test".to_vec()).into(),
        signature_key: signer.public_key().into(),
    }
}

fn assert_suites(actual: &Capabilities, expected: &Capabilities) {
    let actual: Vec<_> = actual
        .ciphersuites()
        .iter()
        .filter(|suite| !suite.is_grease())
        .copied()
        .collect();
    assert_eq!(actual, expected.ciphersuites());
}

#[test]
fn implicit_capabilities_follow_the_provider_for_every_suite() {
    let provider = Provider::in_memory();
    let expected = Capabilities::for_provider(provider.crypto());
    for suite in provider.crypto().supported_ciphersuites() {
        let signer = ReallyMeSuiteSigner::generate(suite.signature_algorithm()).unwrap();
        let config = MlsGroupCreateConfig::builder().ciphersuite(suite).build();
        let group = MlsGroup::new(&provider, &signer, &config, credential(&signer)).unwrap();
        assert_suites(group.own_leaf_node().unwrap().capabilities(), &expected);
        let group = MlsGroup::builder()
            .ciphersuite(suite)
            .build(&provider, &signer, credential(&signer))
            .unwrap();
        assert_suites(group.own_leaf_node().unwrap().capabilities(), &expected);
        let package = KeyPackage::builder()
            .build(suite, &provider, &signer, credential(&signer))
            .unwrap();
        assert_suites(package.key_package().leaf_node().capabilities(), &expected);
    }
}

#[test]
fn explicit_capabilities_are_preserved_even_when_equal_to_global_defaults() {
    let provider = Provider::in_memory();
    let suite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    let signer = ReallyMeSuiteSigner::generate(suite.signature_algorithm()).unwrap();
    for expected in [
        Capabilities::default(),
        Capabilities::new(None, Some(&[suite]), None, None, None),
        Capabilities::new(None, Some(&[]), None, None, None),
    ] {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(suite)
            .capabilities(expected.clone())
            .build();
        let group =
            MlsGroup::new(&provider, &signer, &config.clone(), credential(&signer)).unwrap();
        assert_suites(group.own_leaf_node().unwrap().capabilities(), &expected);
        let group = MlsGroup::builder()
            .ciphersuite(suite)
            .with_capabilities(expected.clone())
            .build(&provider, &signer, credential(&signer))
            .unwrap();
        assert_suites(group.own_leaf_node().unwrap().capabilities(), &expected);
        let package = KeyPackage::builder()
            .leaf_node_capabilities(expected.clone())
            .build(suite, &provider, &signer, credential(&signer))
            .unwrap();
        assert_suites(package.key_package().leaf_node().capabilities(), &expected);
    }
}

#[test]
fn serialized_capabilities_preserve_legacy_defaults_without_format_changes() {
    let provider = Provider::in_memory();
    for suite in provider.crypto().supported_ciphersuites() {
        let signer = ReallyMeSuiteSigner::generate(suite.signature_algorithm()).unwrap();
        let implicit = MlsGroupCreateConfig::builder().ciphersuite(suite).build();
        let explicit = MlsGroupCreateConfig::builder()
            .ciphersuite(suite)
            .capabilities(Capabilities::default())
            .build();
        let encoded = serde_json::to_value(&implicit).unwrap();
        assert!(encoded.get("capabilities_source").is_none());
        assert_eq!(encoded, serde_json::to_value(&explicit).unwrap());
        // The existing format cannot distinguish these two configurations.
        // Preserve its historical default inference, including private suites.
        let decoded: MlsGroupCreateConfig = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(encoded, serde_json::to_value(&decoded).unwrap());
        let group = MlsGroup::new(&provider, &signer, &decoded, credential(&signer)).unwrap();
        assert_suites(
            group.own_leaf_node().unwrap().capabilities(),
            &Capabilities::for_provider(provider.crypto()),
        );
        assert_eq!(implicit, decoded);

        for expected in [
            Capabilities::new(None, Some(&[suite]), None, None, None),
            Capabilities::new(None, Some(&[]), None, None, None),
        ] {
            let config = MlsGroupCreateConfig::builder()
                .ciphersuite(suite)
                .capabilities(expected.clone())
                .build();
            let mut encoded = serde_json::to_value(config).unwrap();
            // Serialized input must not override the internal inference rule
            // and replace a non-default list with the provider's full list.
            encoded["capabilities_source"] = serde_json::json!("Provider");
            let decoded: MlsGroupCreateConfig = serde_json::from_value(encoded).unwrap();
            let group = MlsGroup::new(&provider, &signer, &decoded, credential(&signer)).unwrap();
            assert_suites(group.own_leaf_node().unwrap().capabilities(), &expected);
        }
    }
}

#[test]
#[allow(deprecated)]
fn external_join_defaults_follow_the_provider_and_preserve_explicit_policies() {
    let crypto = openmls_reallyme_provider::CryptoProvider;
    for suite in crypto.supported_ciphersuites() {
        for use_legacy_api in [false, true] {
            for explicit in [
                None,
                Some(Capabilities::new(None, Some(&[suite]), None, None, None)),
            ] {
                let owner = Provider::in_memory();
                let joiner = Provider::in_memory();
                let owner_signer =
                    ReallyMeSuiteSigner::generate(suite.signature_algorithm()).unwrap();
                let joiner_signer =
                    ReallyMeSuiteSigner::generate(suite.signature_algorithm()).unwrap();
                let config = MlsGroupCreateConfig::builder().ciphersuite(suite).build();
                let owner_credential = CredentialWithKey {
                    credential: BasicCredential::new(b"external join owner".to_vec()).into(),
                    signature_key: owner_signer.public_key().into(),
                };
                let mut owner_group =
                    MlsGroup::new(&owner, &owner_signer, &config, owner_credential).unwrap();
                let group_info = MlsMessageIn::from(
                    owner_group
                        .export_group_info(owner.crypto(), &owner_signer, true)
                        .unwrap(),
                )
                .into_verifiable_group_info()
                .unwrap();
                let expected = explicit
                    .clone()
                    .unwrap_or_else(|| Capabilities::for_provider(joiner.crypto()));
                let (mut joined_group, commit) = if use_legacy_api {
                    let (group, commit, _) = MlsGroup::join_by_external_commit(
                        &joiner,
                        &joiner_signer,
                        None,
                        group_info,
                        config.join_config(),
                        explicit,
                        None,
                        &[],
                        credential(&joiner_signer),
                    )
                    .unwrap();
                    (group, commit)
                } else {
                    let mut builder = MlsGroup::external_commit_builder()
                        .build_group(&joiner, group_info, credential(&joiner_signer))
                        .unwrap();
                    if let Some(capabilities) = explicit {
                        builder = builder.leaf_node_parameters(
                            LeafNodeParameters::builder()
                                .with_capabilities(capabilities)
                                .build(),
                        );
                    }
                    let (group, bundle) = builder
                        .load_psks(joiner.storage())
                        .unwrap()
                        .build(joiner.rand(), joiner.crypto(), &joiner_signer, |_| true)
                        .unwrap()
                        .finalize(&joiner)
                        .unwrap();
                    (group, bundle.into_contents().0)
                };
                if joined_group.pending_commit().is_some() {
                    joined_group.merge_pending_commit(&joiner).unwrap();
                }
                assert_suites(
                    joined_group.own_leaf_node().unwrap().capabilities(),
                    &expected,
                );
                // Verify the resulting leaf on an existing member, not just in
                // the joining client's locally constructed group state.
                let processed = owner_group
                    .process_message(
                        &owner,
                        MlsMessageIn::from(commit).into_protocol_message().unwrap(),
                    )
                    .unwrap();
                let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
                else {
                    panic!("expected an external commit");
                };
                owner_group.merge_staged_commit(&owner, *staged).unwrap();
                assert_eq!(
                    owner_group.epoch_authenticator(),
                    joined_group.epoch_authenticator()
                );

                // Defaulting a new external leaf must not change the existing
                // member update path: an omitted list there preserves its leaf.
                let update = joined_group
                    .self_update(&joiner, &joiner_signer, LeafNodeParameters::default())
                    .unwrap()
                    .into_contents()
                    .0;
                joined_group.merge_pending_commit(&joiner).unwrap();
                assert_suites(
                    joined_group.own_leaf_node().unwrap().capabilities(),
                    &expected,
                );
                let processed = owner_group
                    .process_message(
                        &owner,
                        MlsMessageIn::from(update).into_protocol_message().unwrap(),
                    )
                    .unwrap();
                let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
                else {
                    panic!("expected a member update commit");
                };
                owner_group.merge_staged_commit(&owner, *staged).unwrap();
                assert_eq!(
                    owner_group.epoch_authenticator(),
                    joined_group.epoch_authenticator()
                );
            }
        }
    }
}
