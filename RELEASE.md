<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: MIT
-->

# Release Policy

ReallyMe releases of this fork must be reproducible, reviewable, and explicit
about their upstream base. Release notes should name the upstream OpenMLS commit
or tag, the ReallyMe fork commit, the supported ciphersuites, and the exact
`reallyme-crypto` version used by the ReallyMe provider.

## Required Checks

Run the relevant workspace gates before a release candidate:

```sh
cargo fmt --check
cargo check --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Provider releases must also run focused ReallyMe interoperability and MLS flow
tests for each supported ciphersuite. Dependency upgrades that affect crypto,
serialization, storage, credentials, or FFI require release notes explaining the
review and test evidence.

## Dependency Pinning

The ReallyMe provider pins `reallyme-crypto` exactly because cryptographic
behavior is part of the reviewed provider surface. Upgrading that dependency is
a release event, not routine dependency hygiene.

## Publishing

ReallyMe-only fork crates use `publish = false` unless ReallyMe explicitly
decides to publish a public package. Internal production consumers should pin
the reviewed Git revision or release tag.
