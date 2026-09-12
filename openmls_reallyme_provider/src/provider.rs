// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT

use core::fmt;

use openmls_traits::{storage::StorageProvider, OpenMlsProvider};

use crate::CryptoProvider;

/// An OpenMLS provider backed by ReallyMe Crypto and caller-selected storage.
///
/// Storage is generic so production applications can supply their audited,
/// persistent storage implementation without another provider adapter.
pub struct Provider<S> {
    crypto: CryptoProvider,
    storage: S,
}

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
impl Provider<openmls_memory_storage::MemoryStorage> {
    /// Construct the behavior-compatible in-memory provider.
    ///
    /// This constructor is intentionally available only with `test-utils` so a
    /// production build cannot silently select ephemeral MLS state storage.
    pub fn in_memory() -> Self {
        Self::new(openmls_memory_storage::MemoryStorage::default())
    }
}

#[cfg(feature = "test-utils")]
impl Default for Provider<openmls_memory_storage::MemoryStorage> {
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

#[cfg(test)]
mod tests {
    use super::Provider;

    struct SensitiveStorage;

    impl core::fmt::Debug for SensitiveStorage {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
