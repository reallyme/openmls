//! End-to-end OpenMLS flow through the ReallyMe provider.

#![cfg(feature = "mls-flow-tests")]
#![allow(clippy::expect_used)]

use openmls::prelude::*;
use openmls_reallyme_provider::{Provider, ReallyMeSigner};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

#[test]
fn complete_mls_flow_uses_reallyme_provider_and_signers() {
    let alice_provider = Provider::in_memory();
    let bob_provider = Provider::in_memory();
    let alice_signer = ReallyMeSigner::generate().expect("Alice signer generation should succeed");
    let bob_signer = ReallyMeSigner::generate().expect("Bob signer generation should succeed");
    let alice_credential = CredentialWithKey {
        credential: BasicCredential::new(b"Alice".to_vec()).into(),
        signature_key: alice_signer.public_key().as_slice().into(),
    };
    let bob_credential = CredentialWithKey {
        credential: BasicCredential::new(b"Bob".to_vec()).into(),
        signature_key: bob_signer.public_key().as_slice().into(),
    };

    let bob_key_package = KeyPackage::builder()
        .build(CIPHERSUITE, &bob_provider, &bob_signer, bob_credential)
        .expect("Bob key package generation should succeed");
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
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

    let plaintext = b"ReallyMe provider MLS application message";
    let message = alice_group
        .create_message(&alice_provider, &alice_signer, plaintext)
        .expect("Alice should encrypt an application message")
        .into_protocol_message()
        .expect("application output should be a protocol message");
    let processed = bob_group
        .process_message(&bob_provider, message)
        .expect("Bob should process Alice's message");
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => {
            assert_eq!(application.into_bytes(), plaintext);
        }
        other => {
            assert!(
                matches!(other, ProcessedMessageContent::ApplicationMessage(_)),
                "expected an application message"
            );
        }
    }
}
