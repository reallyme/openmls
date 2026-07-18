// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT

use std::fmt;

use openmls_traits::random::OpenMlsRand;
use reallyme_crypto::{
    core::RngOutputKind,
    csprng::{OsSecureRandom, SecureRandom},
};
use thiserror::Error;

use crate::CryptoProvider;

/// Fixed, non-sensitive reasons for provider randomness failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandErrorReason {
    /// The operating system entropy source was unavailable.
    EntropyUnavailable,
    /// The requested allocation could not be represented or reserved.
    AllocationFailed,
}

impl fmt::Display for RandErrorReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::EntropyUnavailable => "entropy unavailable",
            Self::AllocationFailed => "random output allocation failed",
        };
        formatter.write_str(description)
    }
}

/// Error returned by the ReallyMe OpenMLS randomness provider.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RandError {
    /// Secure random generation failed for a fixed, non-sensitive reason.
    #[error("secure random generation failed: {reason}")]
    Generation {
        /// Machine-readable failure reason.
        reason: RandErrorReason,
    },
}

impl CryptoProvider {
    pub(crate) fn fill_random(output: &mut [u8]) -> Result<(), RandError> {
        let mut random = OsSecureRandom;
        random
            .fill_secure(output, RngOutputKind::Generic)
            .map_err(|_| RandError::Generation {
                reason: RandErrorReason::EntropyUnavailable,
            })
    }
}

impl OpenMlsRand for CryptoProvider {
    type Error = RandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut output = [0u8; N];
        Self::fill_random(&mut output)?;
        Ok(output)
    }

    fn random_vec(&self, length: usize) -> Result<Vec<u8>, Self::Error> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| RandError::Generation {
                reason: RandErrorReason::AllocationFailed,
            })?;
        output.resize(length, 0);
        Self::fill_random(&mut output)?;
        Ok(output)
    }
}
