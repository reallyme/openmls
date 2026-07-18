<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: MIT
-->

# Security Policy

This fork is security-sensitive infrastructure. We treat MLS state-machine
bugs, provider divergence, unsupported ciphersuite negotiation, downgrade
acceptance, key-material exposure, storage-boundary mistakes, and dependency
drift as security-relevant.

## Reporting

Please report vulnerabilities privately before public disclosure. Use
[GitHub private vulnerability reporting](https://github.com/reallyme/openmls/security/advisories/new)
for this repository when available; otherwise use the security contact listed
for ReallyMe LLC.

Include the affected crate, version or commit, ciphersuite, platform, and the
smallest reproduction you can share without exposing private keys, plaintext
messages, production group state, or personally identifiable information.

## Scope

In scope:

- panics or unchecked error paths reachable through attacker-controlled MLS
  messages;
- ReallyMe provider behavior that diverges from the reviewed OpenMLS provider
  contract;
- acceptance of unsupported ciphersuites or unexpected downgrade paths;
- leakage of raw key material, plaintext, credentials, or backend exception
  text through errors, logs, FFI, or test fixtures;
- dependency upgrades that alter cryptographic behavior without updated tests.

Out of scope:

- cryptographic primitive implementation bugs that belong to the separate
  `reallyme-crypto` repository;
- unsupported platform combinations that fail closed with typed errors;
- experimental ciphersuites or draft features that are not documented as
  production surfaces.

## Supported Versions

This fork is pre-1.0 from ReallyMe's perspective. Production deployments should
pin exact Git revisions, release tags, or package versions and should consume
only the ReallyMe-supported provider and ciphersuite surfaces documented in this
repository.
