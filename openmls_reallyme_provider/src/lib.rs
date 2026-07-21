// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
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
use openmls_traits::{storage::StorageProvider, OpenMlsProvider};
#[cfg(any(feature = "native", feature = "wasm"))]
use std::fmt;

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
mod random;
#[cfg(any(feature = "native", feature = "wasm"))]
mod signer;

#[cfg(any(feature = "native", feature = "wasm"))]
pub use crypto::CryptoProvider;
#[cfg(all(any(feature = "native", feature = "wasm"), feature = "test-utils"))]
pub use openmls_memory_storage::{MemoryStorage, MemoryStorageError};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use random::{RandError, RandErrorReason};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use signer::{ReallyMeSigner, ReallyMeSuiteSigner};

/// An OpenMLS provider backed by ReallyMe Crypto and caller-selected storage.
///
/// Storage is generic so production applications can supply their audited,
/// persistent storage implementation without another provider adapter.
#[cfg(any(feature = "native", feature = "wasm"))]
pub struct Provider<S> {
    crypto: CryptoProvider,
    storage: S,
}

#[cfg(any(feature = "native", feature = "wasm"))]
impl<S> fmt::Debug for Provider<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Storage contains serialized MLS key material. Do not require S to
        // implement Debug because delegating to it could disclose the entire
        // key store through logs, panic capture, or telemetry.
        formatter
            .debug_struct("Provider")
            .field("crypto", &self.crypto)
            .field("storage", &"[REDACTED]")
            .finish()
    }
}

#[cfg(any(feature = "native", feature = "wasm"))]
impl<S> Provider<S> {
    /// Construct a provider with the given OpenMLS storage implementation.
    pub fn new(storage: S) -> Self {
        Self {
            crypto: CryptoProvider,
            storage,
        }
    }

    /// Consume the provider and return its storage implementation.
    pub fn into_storage(self) -> S {
        self.storage
    }
}

#[cfg(all(any(feature = "native", feature = "wasm"), feature = "test-utils"))]
impl Provider<MemoryStorage> {
    /// Construct the behavior-compatible in-memory provider.
    ///
    /// This constructor is intentionally available only with `test-utils` so a
    /// production build cannot silently select ephemeral MLS state storage.
    pub fn in_memory() -> Self {
        Self::new(MemoryStorage::default())
    }
}

#[cfg(all(any(feature = "native", feature = "wasm"), feature = "test-utils"))]
impl Default for Provider<MemoryStorage> {
    fn default() -> Self {
        Self::in_memory()
    }
}

#[cfg(any(feature = "native", feature = "wasm"))]
impl<S> OpenMlsProvider for Provider<S>
where
    S: StorageProvider<{ openmls_traits::storage::CURRENT_VERSION }>,
{
    type CryptoProvider = CryptoProvider;
    type RandProvider = CryptoProvider;
    type StorageProvider = S;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

#[cfg(all(test, any(feature = "native", feature = "wasm")))]
mod tests {
    use super::*;

    struct SensitiveStorage;

    impl fmt::Debug for SensitiveStorage {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("PRIVATE_MLS_STATE")
        }
    }

    #[test]
    fn provider_debug_redacts_storage() {
        let provider = Provider::new(SensitiveStorage);
        let rendered = format!("{provider:?}");

        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("PRIVATE_MLS_STATE"));
    }
}
