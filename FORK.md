<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: MIT
-->

# Fork Policy

This repository is a narrow ReallyMe fork of OpenMLS. The fork exists to support
ReallyMe's provider boundary, conformance vectors, release process, and future
approved ciphersuite work while staying close enough to upstream for routine
merges.

## Principles

- Keep upstream protocol code unchanged unless the change is required for a
  documented ReallyMe fork point.
- Prefer provider crates and feature gates over broad edits to shared OpenMLS
  state machines.
- Document every private ciphersuite identifier, serialization change,
  validation rule, and downgrade rule before enabling it.
- Keep ReallyMe-only crates unpublished unless there is an explicit public
  release decision.
- Treat dependency upgrades as security-relevant changes when they affect
  cryptography, serialization, storage, or FFI boundaries.

## Upstream Sync

The expected remotes are:

```sh
git remote add upstream https://github.com/openmls/openmls.git
git remote add origin https://github.com/reallyme/openmls.git
```

Before a sync, record the current ReallyMe test baseline and review upstream
changes touching ciphersuites, HPKE, OpenMLS traits, storage traits, credential
handling, serialization, or downgrade validation. After a sync, rerun the
ReallyMe provider tests before merging.

For the public `main` branch, merge upstream instead of rebasing already
published ReallyMe commits:

```sh
git fetch upstream
git log --oneline --left-right main...upstream/main
git merge --no-ff upstream/main
```

Resolve conflicts by preserving upstream behavior outside the fork points
listed below. Run [RELEASE.md](RELEASE.md) before pushing the merge. A temporary
integration branch may be rebased locally, but the shared branch must not be
force-pushed as part of routine synchronization.

## ReallyMe Fork Points

Current production fork points:

- `openmls_reallyme_provider`: an OpenMLS provider backed by `reallyme-crypto`.
- `traits/src/types.rs`: the feature-gated hybrid KEM and private provisional
  ciphersuite identifier, plus revision-pinned draft component mappings.
- `openmls_rust_crypto` and `libcrux_crypto`: explicit rejection of draft
  combinations those providers cannot implement; they must never advertise a
  suite that their `supports` implementation rejects.
- `openmls/src/group/mls_group/builder.rs` and
  `openmls/src/key_packages/mod.rs`: provider-derived default capabilities.
  Explicit caller capability policies remain authoritative.

Current test and infrastructure fork points:

- `openmls_test`, `openmls/Cargo.toml`, and the test-only capability entry in
  `openmls/src/treesync/node/leaf_node/capabilities.rs`: opt-in expansion of
  the generic OpenMLS corpus over the ReallyMe provider's exact allowlist.
- `openmls/src/group/tests_and_kats/utils.rs`,
  `openmls/src/storage/kat_storage_stability.rs`, and
  `openmls/test_vectors/storage-stability.json`: provider construction and
  persisted-state vectors for every ReallyMe suite.
- `openmls/src/group/tests_and_kats/tests/virtual_clients.rs`: executable-lane
  sentinel and provider capability guards for generic virtual-client tests.
- `openmls/src/group/mls_group/tests_and_kats/tests/mls_group.rs` and
  `openmls/tests/book_code.rs`: explicit suite selection required after
  provider-derived defaults replaced hardcoded global capabilities.
- `.github/workflows/reallyme_provider.yml`: fork-provider MSRV, native/WASM,
  dependency-isolation, conformance, and scheduled generic-corpus gates.
- `.github/workflows/build.yml`, `build_test_workspace.yml`, `clippy.yml`,
  `gh-pages.yml`, and `wasm-bench.yml`: immutable action pins, locked
  dependency resolution, and the ReallyMe provider's Rust 1.96 workspace
  floor.
- `.github/workflows/fuzz.yml`, `fuzz/Cargo.toml`, and the ReallyMe provider
  fuzz target: malformed HPKE and signature-input coverage.
- `compat_tests` and `book/src/user_manual/migration.md`: current-version
  storage migration tests and documentation, including the 0.7/0.8 to 0.9
  bridges. These are kept outside the root workspace because they intentionally
  resolve multiple incompatible OpenMLS versions.
- `sqlx_storage`: SQLx 0.9 adaptation, native migration-table naming, and
  lifecycle coverage. This crate remains outside the root workspace and must
  be formatted, linted, and tested through its own manifest.
- `openmls-wasm/Cargo.toml`, `openmls-wasm/build.sh`, and
  `openmls-wasm/check-size.sh`: locked and explicitly feature-scoped WASM
  build surface.
- `serialization_helpers/Cargo.toml`: disables Postcard's unnecessary default
  feature in host-only tests to exclude the unmaintained `atomic-polyfill`
  dependency.
- root `Cargo.toml`, `Cargo.lock`, `deny.toml`, and dependency-only changes in
  member `Cargo.toml` files: workspace membership, exact dependency resolution,
  current compatible dependency versions, and deployable-provider policy.
- `rust-toolchain.toml`: pins development and ordinary CI to Rust 1.98.1 while
  the dedicated MSRV job continues to enforce the published Rust 1.96 floor.

Current repository-policy fork points are `README.md`, `README.upstream.md`,
`LICENSE`, `SECURITY.md`, `RELEASE.md`, `AUDIT_SCOPE.md`,
`THIRD_PARTY_NOTICES.md`, this file, and `PQ_MLS_SUITES.md`. Preserve upstream
attribution while resolving these files; do not replace the fork's deployment
warnings with upstream's general-purpose documentation.

Future fork points must be added here before implementation, including their
reason, affected modules, codepoint ownership, test vectors, and rollback plan.
The standards-tracking PQ MLS expansion is recorded in
[PQ_MLS_SUITES.md](PQ_MLS_SUITES.md).
