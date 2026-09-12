<div align="center">

# ReallyMe OpenMLS Fork

**Post-quantum MLS ciphersuites for OpenMLS, backed by ReallyMe Crypto.**

[![ReallyMe provider](https://github.com/reallyme/openmls/actions/workflows/reallyme_provider.yml/badge.svg)](https://github.com/reallyme/openmls/actions/workflows/reallyme_provider.yml)
[![Workspace](https://github.com/reallyme/openmls/actions/workflows/build_test_workspace.yml/badge.svg)](https://github.com/reallyme/openmls/actions/workflows/build_test_workspace.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license)

**[PQ suites](PQ_MLS_SUITES.md) · [Release](RELEASE.md) · [Security](SECURITY.md) · [Fork policy](FORK.md) · [Provider source](https://github.com/reallyme/openmls/tree/main/openmls_reallyme_provider)**

</div>

---

[OpenMLS](https://github.com/openmls/openmls) is a Rust implementation of the
Messaging Layer Security protocol defined in
[RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420). ReallyMe maintains
this fork to add post-quantum MLS ciphersuites backed by
[`reallyme-crypto`](https://github.com/reallyme/crypto), while staying close to
upstream OpenMLS.

The fork currently supports six PQ ciphersuites. The cryptographic backend is
pinned to an exact release, and changes to cryptographic dependencies or
provisional ciphersuite mappings go through the fork's release review.

## Post-Quantum Ciphersuites

Enable `draft-ietf-mls-pq-ciphersuites` to make the six PQ ciphersuites
available.

Five suites track
[Post-Quantum and Post-Quantum/Traditional Hybrid Ciphersuites for MLS](https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/).
They use AES-256-GCM with SHA-384. The X-Wing compatibility suite uses
ChaCha20-Poly1305 with SHA-256.

| Ciphersuite | Key establishment | Signature | Wire |
|---|---|---|---:|
| **X-Wing compatibility** | ML-KEM-768 + X25519 | Ed25519 | `0x004D` |
| **ML-KEM-768 PQ** | ML-KEM-768 | ML-DSA-65 | `0x0051` |
| **ML-KEM-1024 PQ** | ML-KEM-1024 | ML-DSA-87 | `0x0907` |
| **ML-KEM-768/X25519 hybrid** | ML-KEM-768 + X25519 | Ed25519 | `0x004E` |
| **ML-KEM-1024/P-384 hybrid** | ML-KEM-1024 + P-384 | P-384 | `0xF043` |
| **ML-KEM-1024 + P-384 signature** | ML-KEM-1024 | P-384 | `0x0042` |

<details>
<summary>Rust ciphersuite variants</summary>

| Suite | `Ciphersuite` variant |
|---|---|
| X-Wing compatibility | `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` |
| ML-KEM-768 PQ | `MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65` |
| ML-KEM-1024 PQ | `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87` |
| ML-KEM-1024 + P-384 signature | `MLS_192_MLKEM1024_AES256GCM_SHA384_P384` |
| ML-KEM-1024/P-384 hybrid | `MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384` |
| ML-KEM-768/X25519 hybrid | `MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519` |

</details>

These identifiers do not yet have final IANA MLS assignments. Five currently
use unassigned registry values; the ML-KEM-1024/P-384 hybrid uses a private-use
value.

Until final assignments are available, communicating implementations must agree
on the ciphersuite identifiers they use. Pinning the same fork revision ensures
the mappings remain consistent.

See [PQ_MLS_SUITES.md](PQ_MLS_SUITES.md) for the exact mappings, registry
status, and interoperability requirements.

## Provider

`openmls_reallyme_provider` implements the OpenMLS provider traits using
`reallyme-crypto` for HPKE, AEAD, hashing, signatures, and randomness.
`reallyme-crypto` is pinned to an exact release so that changes to the
cryptographic backend are explicit and reviewable.

```toml
[dependencies]
openmls = { git = "https://github.com/reallyme/openmls.git", rev = "<reviewed-commit>", features = ["draft-ietf-mls-pq-ciphersuites"] }
openmls_reallyme_provider = { git = "https://github.com/reallyme/openmls.git", rev = "<reviewed-commit>", features = ["draft-ietf-mls-pq-ciphersuites"] }
```

Use the same fixed revision or release tag for both crates rather than following
`main`.

```rust,ignore
use openmls::prelude::{
    Capabilities, Ciphersuite, MlsGroupCreateConfig, OpenMlsProvider as _,
};
use openmls_reallyme_provider::{Provider, ReallyMeSuiteSigner};

let storage = AuditedDurableStorage::open()?;
let provider = Provider::new(storage);

let suite =
    Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384;
let signer =
    ReallyMeSuiteSigner::generate(suite.signature_algorithm())?;

let group_config = MlsGroupCreateConfig::builder()
    .ciphersuite(suite)
    .capabilities(Capabilities::for_provider(provider.crypto()))
    .build();
```

Production callers provide durable storage through `Provider::new(storage)`.
The in-memory provider is available only with `test-utils`.

Provider source lives in
[`openmls_reallyme_provider`](https://github.com/reallyme/openmls/tree/main/openmls_reallyme_provider).

## Fork Policy

Changes specific to ReallyMe should remain narrow and easy to distinguish from
upstream OpenMLS. Prefer provider crates, feature gates, and focused fork points
over changes to shared protocol code.

Upstream changes are merged from `openmls/main` through pull requests. See
[FORK.md](FORK.md) for the fork points and upstream sync process.

## Release

Passing the required checks on `main` is not by itself a production release.

[RELEASE.md](RELEASE.md) defines the release checks for the provider,
ciphersuites, interoperability, and dependency graph.

The term **reviewed** in this repository refers to this local review and release
process. It does not mean that the ReallyMe additions have received an
independent security audit or formal evaluation.

## Security

Security issues should be reported according to
[SECURITY.md](SECURITY.md).

## License

This repository contains upstream OpenMLS code and ReallyMe modifications.
Unless a file-level notice states otherwise, the code is licensed under the MIT
License. See [LICENSE](https://github.com/reallyme/openmls/blob/main/LICENSE).

`reallyme-crypto` is distributed separately under the Apache License, Version
2.0, and is not relicensed by this repository.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for third-party
attributions and notices.

## Copyright and Trademarks

Upstream OpenMLS portions are copyright © 2020 OpenMLS Authors. ReallyMe
modifications are copyright © 2026 ReallyMe LLC.

OpenMLS is a trademark or trade name of the OpenMLS project and its respective
owners. ReallyMe does not claim ownership of the OpenMLS name or marks.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
