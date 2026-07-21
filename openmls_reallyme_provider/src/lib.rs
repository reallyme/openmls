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

use openmls_traits::{storage::StorageProvider, OpenMlsProvider};

mod crypto;
#[cfg(feature = "virtual-clients-draft")]
mod ff1;
mod hpke;
mod kdf;
mod random;
mod signer;

pub use crypto::CryptoProvider;
#[cfg(feature = "test-utils")]
pub use openmls_memory_storage::{MemoryStorage, MemoryStorageError};
pub use random::{RandError, RandErrorReason};
pub use signer::{ReallyMeSigner, ReallyMeSuiteSigner};

/// An OpenMLS provider backed by ReallyMe Crypto and caller-selected storage.
///
/// Storage is generic so production applications can supply their audited,
/// persistent storage implementation without another provider adapter.
#[derive(Debug)]
pub struct Provider<S> {
    crypto: CryptoProvider,
    storage: S,
}

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

#[cfg(feature = "test-utils")]
impl Provider<MemoryStorage> {
    /// Construct the behavior-compatible in-memory provider.
    ///
    /// This constructor is intentionally available only with `test-utils` so a
    /// production build cannot silently select ephemeral MLS state storage.
    pub fn in_memory() -> Self {
        Self::new(MemoryStorage::default())
    }
}

#[cfg(feature = "test-utils")]
impl Default for Provider<MemoryStorage> {
    fn default() -> Self {
        Self::in_memory()
    }
}

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
