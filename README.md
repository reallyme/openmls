<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: MIT
-->

# ReallyMe OpenMLS Fork

This repository is ReallyMe's narrow production fork of
[OpenMLS](https://github.com/openmls/openmls), a Rust implementation of the
Messaging Layer Security protocol specified in
[RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420).

The fork is intentionally small. ReallyMe-specific work should stay close to
upstream OpenMLS and focus on provider integration, conformance, audited release
discipline, and future ciphersuite work that is explicitly documented before it
is enabled.

## Current ReallyMe Surface

The first ReallyMe-specific crate is `openmls_reallyme_provider`, an unpublished
OpenMLS provider backed by `reallyme-crypto`.

With `draft-ietf-mls-pq-ciphersuites` enabled, the provider advertises exactly
one behavior-compatible MLS ciphersuite:

`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`

That provider routes X-Wing-768, ChaCha20-Poly1305, SHA-256, HMAC/HKDF,
Ed25519, and operating-system randomness through `reallyme-crypto`. It does not
change MLS serialization, group state, downgrade validation, or wire protocol
behavior.

## Upstream Relationship

ReallyMe maintains this fork so it can carry a small number of production
changes while continuing to rebase against upstream OpenMLS.

- Upstream source: <https://github.com/openmls/openmls>
- ReallyMe fork: <https://github.com/reallyme/openmls>
- Original upstream README snapshot: [README.upstream.md](README.upstream.md)
- Fork maintenance notes: [FORK.md](FORK.md)

OpenMLS modules that are not explicitly ReallyMe-specific should remain
upstream-shaped. Prefer provider crates, feature gates, and documented private
fork points over broad edits to shared protocol code.

## Production Status

The ReallyMe provider is the current production-oriented target for this fork.
Future CNSA-oriented or ReallyMe-private MLS ciphersuites are not production
surfaces until their identifiers, validation rules, downgrade policy, vectors,
and audit boundary are documented and tested.

For security and release handling, see:

- [SECURITY.md](SECURITY.md)
- [RELEASE.md](RELEASE.md)
- [AUDIT_SCOPE.md](AUDIT_SCOPE.md)
- [PQ_MLS_SUITES.md](PQ_MLS_SUITES.md)
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

## Development Gates

Before merging production changes, run the relevant focused tests and the
workspace checks appropriate for the change:

```sh
cargo fmt --check
cargo check --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Crypto-provider changes must also pass the ReallyMe provider interoperability
and MLS flow tests for the supported ciphersuite.

## License

This repository contains upstream OpenMLS code and ReallyMe modifications to
OpenMLS. Unless a file-level SPDX identifier states otherwise, the code in this
repository is licensed under the MIT License. See [LICENSE](LICENSE).

External repositories and dependencies are licensed under their respective
licenses. In particular, `reallyme-crypto` is distributed separately under the
Apache License, Version 2.0, and is not relicensed by this repository.

## Copyright And Trademarks

Copyright © 2026 by ReallyMe LLC.

OpenMLS is a trademark or trade name of the OpenMLS project and its respective
owners. ReallyMe does not claim ownership of the OpenMLS name or marks.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
