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
- `traits/src/types.rs`: feature-gated draft KEM, KDF, and ciphersuite identifiers.
- `openmls_rust_crypto` and `libcrux_crypto`: explicit rejection of draft
  combinations those providers cannot implement; they must never advertise a
  suite that their `supports` implementation rejects.

Future fork points must be added here before implementation, including their
reason, affected modules, codepoint ownership, test vectors, and rollback plan.
The standards-tracking PQ MLS expansion is recorded in
[PQ_MLS_SUITES.md](PQ_MLS_SUITES.md).
