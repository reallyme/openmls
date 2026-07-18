<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: MIT
-->

# Fork Policy

This repository is a narrow ReallyMe fork of OpenMLS. The fork exists to support
ReallyMe's provider boundary, conformance vectors, release process, and future
approved ciphersuite work while staying close enough to upstream for routine
rebases.

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

## ReallyMe Fork Points

Current fork point:

- `openmls_reallyme_provider`: an OpenMLS provider backed by `reallyme-crypto`.

Future fork points must be added here before implementation, including their
reason, affected modules, codepoint ownership, test vectors, and rollback plan.
