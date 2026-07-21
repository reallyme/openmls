// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT

//! End-to-end OpenMLS flows through every suite advertised by the provider.

#![cfg(feature = "mls-flow-tests")]
#![allow(clippy::expect_used)]

use openmls::prelude::*;
use openmls_reallyme_provider::{Provider, ReallyMeSuiteSigner};
use tls_codec::Serialize as _;

const APPLICATION_PLAINTEXT: &[u8] = b"ReallyMe provider MLS application message";
const EXPORT_LABEL: &str = "reallyme/provider/epoch-proof";

fn protocol_encoding(message: &ProtocolMessage) -> Vec<u8> {
    match message {
        ProtocolMessage::PrivateMessage(message) => message
            .tls_serialize_detached()
            .expect("private protocol message should serialize"),
        ProtocolMessage::PublicMessage(message) => message
            .tls_serialize_detached()
            .expect("public protocol message should serialize"),
    }
}

fn complete_mls_flow(ciphersuite: Ciphersuite) {
    let alice_provider = Provider::in_memory();
    let bob_provider = Provider::in_memory();
    let alice_signer = ReallyMeSuiteSigner::generate(ciphersuite.signature_algorithm())
        .expect("Alice signer generation should succeed");
    let bob_signer = ReallyMeSuiteSigner::generate(ciphersuite.signature_algorithm())
        .expect("Bob signer generation should succeed");
    let alice_credential = CredentialWithKey {
        credential: BasicCredential::new(b"Alice".to_vec()).into(),
        signature_key: alice_signer.public_key().into(),
    };
    let bob_credential = CredentialWithKey {
        credential: BasicCredential::new(b"Bob".to_vec()).into(),
        signature_key: bob_signer.public_key().into(),
    };
    // Global OpenMLS defaults intentionally cover draft suites implemented by
    // several providers. Bind each leaf to this provider's exact executable
    // set so it cannot advertise an unsupported or unintended suite.
    let capabilities = Capabilities::for_provider(alice_provider.crypto());

    let bob_key_package = KeyPackage::builder()
        .leaf_node_capabilities(capabilities.clone())
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .expect("Bob key package generation should succeed");
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .capabilities(capabilities)
        .build();
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice_signer,
        &group_config,
        alice_credential,
    )
    .expect("Alice group creation should succeed");
    let (_, welcome, _) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            &[bob_key_package.key_package().to_owned()],
        )
        .expect("adding Bob should succeed");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("Alice should merge the add commit");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("the add operation must produce a Welcome");
    let mut bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        group_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Bob should process the Welcome")
    .into_group(&bob_provider)
    .expect("Bob should join the group");

    let first_message = alice_group
        .create_message(&alice_provider, &alice_signer, APPLICATION_PLAINTEXT)
        .expect("Alice should encrypt the first application message")
        .into_protocol_message()
        .expect("application output should be a protocol message");
    let first_encoding = protocol_encoding(&first_message);
    let first_processed = bob_group
        .process_message(&bob_provider, first_message)
        .expect("Bob should process Alice's first message");
    match first_processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => {
            assert_eq!(application.into_bytes(), APPLICATION_PLAINTEXT);
        }
        other => {
            assert!(
                matches!(other, ProcessedMessageContent::ApplicationMessage(_)),
                "expected an application message"
            );
        }
    }

    // Identical plaintext in one epoch must still produce distinct protected
    // messages. This exercises the sender ratchet generation and guards
    // against accidental key/nonce reuse at the MLS boundary.
    let second_message = alice_group
        .create_message(&alice_provider, &alice_signer, APPLICATION_PLAINTEXT)
        .expect("Alice should encrypt the second application message")
        .into_protocol_message()
        .expect("application output should be a protocol message");
    let second_encoding = protocol_encoding(&second_message);
    assert_ne!(first_encoding, second_encoding);
    let second_processed = bob_group
        .process_message(&bob_provider, second_message)
        .expect("Bob should process Alice's second message");
    assert!(matches!(
        second_processed.into_content(),
        ProcessedMessageContent::ApplicationMessage(_)
    ));

    let reply_plaintext = b"Bob to Alice through the ReallyMe provider";
    let reply = bob_group
        .create_message(&bob_provider, &bob_signer, reply_plaintext)
        .expect("Bob should encrypt a reply")
        .into_protocol_message()
        .expect("Bob's application output should be a protocol message");
    let reply_processed = alice_group
        .process_message(&alice_provider, reply)
        .expect("Alice should process Bob's reply");
    match reply_processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => {
            assert_eq!(application.into_bytes(), reply_plaintext);
        }
        other => {
            assert!(
                matches!(other, ProcessedMessageContent::ApplicationMessage(_)),
                "expected Bob's application message"
            );
        }
    }

    let first_epoch_secret = alice_group
        .export_secret(
            alice_provider.crypto(),
            EXPORT_LABEL,
            b"epoch transition",
            ciphersuite.hash_length(),
        )
        .expect("first epoch export should succeed");
    let (commit, welcome, _) = alice_group
        .self_update(
            &alice_provider,
            &alice_signer,
            LeafNodeParameters::default(),
        )
        .expect("Alice self update should succeed")
        .into_contents();
    assert!(welcome.is_none());
    let processed_commit = bob_group
        .process_message(
            &bob_provider,
            commit
                .into_protocol_message()
                .expect("self update should produce a protocol message"),
        )
        .expect("Bob should process Alice's self update");
    let staged_commit = match processed_commit.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => *staged,
        other => {
            assert!(
                matches!(other, ProcessedMessageContent::StagedCommitMessage(_)),
                "expected a staged commit"
            );
            return;
        }
    };
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("Alice should merge her self update");
    bob_group
        .merge_staged_commit(&bob_provider, staged_commit)
        .expect("Bob should merge Alice's self update");

    let next_epoch_secret = alice_group
        .export_secret(
            alice_provider.crypto(),
            EXPORT_LABEL,
            b"epoch transition",
            ciphersuite.hash_length(),
        )
        .expect("next epoch export should succeed");
    assert_ne!(first_epoch_secret, next_epoch_secret);
    assert_eq!(
        alice_group.epoch_authenticator(),
        bob_group.epoch_authenticator()
    );

    let next_epoch_message = alice_group
        .create_message(&alice_provider, &alice_signer, APPLICATION_PLAINTEXT)
        .expect("Alice should encrypt after the epoch transition")
        .into_protocol_message()
        .expect("application output should be a protocol message");
    let next_epoch_encoding = protocol_encoding(&next_epoch_message);
    assert_ne!(second_encoding, next_epoch_encoding);
    let next_epoch_processed = bob_group
        .process_message(&bob_provider, next_epoch_message)
        .expect("Bob should process the next epoch message");
    assert!(matches!(
        next_epoch_processed.into_content(),
        ProcessedMessageContent::ApplicationMessage(_)
    ));

    let bob_index = bob_group.own_leaf_index();
    let (remove_commit, remove_welcome, _) = alice_group
        .remove_members(&alice_provider, &alice_signer, &[bob_index])
        .expect("Alice should create a commit removing Bob");
    assert!(remove_welcome.is_none());
    let processed_remove = bob_group
        .process_message(
            &bob_provider,
            remove_commit
                .into_protocol_message()
                .expect("remove commit should be a protocol message"),
        )
        .expect("Bob should authenticate the commit removing him");
    let staged_remove = match processed_remove.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => *staged,
        other => {
            assert!(
                matches!(other, ProcessedMessageContent::StagedCommitMessage(_)),
                "expected a staged remove commit"
            );
            return;
        }
    };
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("Alice should merge the remove commit");
    bob_group
        .merge_staged_commit(&bob_provider, staged_remove)
        .expect("Bob should merge the authenticated remove commit");
    assert!(!bob_group.is_active());
    assert_eq!(alice_group.members().count(), 1);
}

#[test]
fn complete_xwing_mls_flow() {
    complete_mls_flow(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519);
}

#[test]
fn complete_mlkem1024_p384_signature_mls_flow() {
    complete_mls_flow(Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384);
}

#[test]
fn complete_mlkem1024_ml_dsa_87_mls_flow() {
    complete_mls_flow(Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87);
}

#[test]
fn complete_hybrid_mlkem1024_p384_mls_flow() {
    complete_mls_flow(Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384);
}
