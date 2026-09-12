// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT

//! ReallyMe Crypto provider for OpenMLS.
//!
//! This crate deliberately supports a narrow cryptographic surface. With the
//! `draft-ietf-mls-pq-ciphersuites` feature enabled, it supports the deployed
//! ReallyMe X-Wing suite and selected draft ML-KEM-1024 profiles. Keeping the
//! provider narrow prevents an application from silently negotiating a suite
//! that has not passed ReallyMe's conformance and interoperability testing.

#![forbid(unsafe_code)]

#[cfg(not(any(feature = "native", feature = "wasm")))]
compile_error!(
    "openmls_reallyme_provider requires a backend: enable the default `native` feature or enable \
     `wasm` when building with --no-default-features"
);

#[cfg(all(target_arch = "wasm32", feature = "native", feature = "wasm"))]
compile_error!(
    "openmls_reallyme_provider cannot enable both `native` and `wasm` on wasm32; disable default \
     features and enable only `wasm`"
);

#[cfg(any(feature = "native", feature = "wasm"))]
mod crypto;
#[cfg(all(
    any(feature = "native", feature = "wasm"),
    feature = "virtual-clients-draft"
))]
mod ff1;
#[cfg(any(feature = "native", feature = "wasm"))]
mod hpke;
#[cfg(any(feature = "native", feature = "wasm"))]
mod kdf;
#[cfg(any(feature = "native", feature = "wasm"))]
mod provider;
#[cfg(any(feature = "native", feature = "wasm"))]
mod random;
#[cfg(any(feature = "native", feature = "wasm"))]
mod signer;

#[cfg(any(feature = "native", feature = "wasm"))]
pub use crypto::CryptoProvider;
#[cfg(all(any(feature = "native", feature = "wasm"), feature = "test-utils"))]
pub use openmls_memory_storage::{MemoryStorage, MemoryStorageError};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use provider::Provider;
#[cfg(any(feature = "native", feature = "wasm"))]
pub use random::{RandError, RandErrorReason};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use signer::{ReallyMeSigner, ReallyMeSuiteSigner};
