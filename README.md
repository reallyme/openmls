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
upstream OpenMLS and focus on provider integration, conformance, reviewed
release discipline, and future ciphersuite work that is explicitly documented
before it is enabled.

The fork-specific additions are not covered by any third-party assessment of
upstream OpenMLS. “Reviewed” in this repository means the documented local
review and release gates; it is not a claim of an independent security audit or
formal evaluation.

## Current ReallyMe Surface

The first ReallyMe-specific crate is `openmls_reallyme_provider`, an unpublished
OpenMLS provider backed by `reallyme-crypto`.

With `draft-ietf-mls-pq-ciphersuites` enabled, the provider advertises the four
suites documented in [PQ_MLS_SUITES.md](PQ_MLS_SUITES.md): the deployed X-Wing
compatibility suite plus the selected ML-KEM-1024, ML-DSA-87, P-384, and hybrid
ML-KEM-1024/P-384 profiles.

The provider delegates HPKE, AEAD, hashes, signatures, and operating-system
randomness to the exactly pinned `reallyme-crypto` release. It does not change
MLS group-state serialization or the MLS state machine. None of the four
provider suite identifiers has a final IANA MLS assignment; the hybrid suite
uses a private-use value while the compatibility values occupy currently
unassigned values. All four are therefore restricted to closed,
revision-pinned deployments.

## Upstream Relationship

ReallyMe maintains this fork so it can carry a small number of production
changes while continuing to merge updates from upstream OpenMLS.

- Upstream source: <https://github.com/openmls/openmls>
- ReallyMe fork: <https://github.com/reallyme/openmls>
- Original upstream README snapshot: [README.upstream.md](README.upstream.md)
- Fork maintenance notes: [FORK.md](FORK.md)

OpenMLS modules that are not explicitly ReallyMe-specific should remain
upstream-shaped. Prefer provider crates, feature gates, and documented private
fork points over broad edits to shared protocol code.

## Production Status

The ReallyMe provider is the current production-oriented target for this fork.
Draft suites are not suitable for arbitrary public federation; deployments must
follow the feature, revision-pinning, durable-storage, and provisional-codepoint
requirements in [PQ_MLS_SUITES.md](PQ_MLS_SUITES.md).

For security and release handling, see:

- [SECURITY.md](SECURITY.md)
- [RELEASE.md](RELEASE.md)
- [AUDIT_SCOPE.md](AUDIT_SCOPE.md)
- [PQ_MLS_SUITES.md](PQ_MLS_SUITES.md)
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

## Development Gates

Before merging production changes, run the relevant focused tests and the
workspace checks appropriate for the change:

The authoritative locked commands, including the memory-safe exhaustive-test
configuration and provider interoperability matrix, are in
[RELEASE.md](RELEASE.md). Crypto-provider changes must pass every advertised
ciphersuite flow, not only the X-Wing compatibility suite.

## License

This repository contains upstream OpenMLS code and ReallyMe modifications to
OpenMLS. Unless a file-level SPDX identifier states otherwise, the code in this
repository is licensed under the MIT License. See the repository's
[LICENSE](https://github.com/reallyme/openmls/blob/main/LICENSE).

External repositories and dependencies are licensed under their respective
licenses. In particular, `reallyme-crypto` is distributed separately under the
Apache License, Version 2.0, and is not relicensed by this repository.

## Copyright And Trademarks

Upstream OpenMLS portions are copyright © 2020 OpenMLS Authors. ReallyMe
modifications are copyright © 2026 ReallyMe LLC. File-level SPDX notices and
the repository's
[LICENSE](https://github.com/reallyme/openmls/blob/main/LICENSE) control where
they provide more specific attribution.

OpenMLS is a trademark or trade name of the OpenMLS project and its respective
owners. ReallyMe does not claim ownership of the OpenMLS name or marks.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
