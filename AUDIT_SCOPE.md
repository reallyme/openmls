<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: MIT
-->

# Audit Scope

The current ReallyMe fork point is an OpenMLS provider backed by
`reallyme-crypto`. It is not, by itself, a FIPS 140-3 validated cryptographic
module or a CNSA 2.0 evaluated MLS product boundary.

## Current Boundary

In scope for the current ReallyMe provider review:

- supported ciphersuite advertisement;
- ReallyMe-backed AEAD, hash, HKDF/HMAC, Ed25519, X-Wing, and randomness calls;
- provider error mapping;
- HPKE bridge behavior for the supported X-Wing and selected draft ML-KEM-1024
  ciphersuites;
- deterministic provider vectors, invalid-input and tamper behavior;
- provider interoperability and per-ciphersuite MLS flow tests;
- epoch transition and repeated-message separation checks.

Outside the current provider boundary:

- OpenMLS core key schedule and group state internals;
- application identity, credential, and authorization policy;
- durable storage implementations supplied by production applications;
- Swift, Kotlin, Java, TypeScript, WASM, JNI, or C ABI adapters not present in
  this repository;
- FIPS 140-3, NIAP, CSfC, or CNSA product evaluation claims.

OpenMLS' provider trait requires signature private keys and decrypted plaintext
to cross the adapter as owned `Vec<u8>` values. The ReallyMe adapter moves
zeroizing backend allocations where the trait permits and the bundled signers
immediately place private keys in `SecretBox`, but it cannot control buffers
after returning them to an arbitrary trait caller. Applications must avoid
cloning those values and must zeroize caller-owned sensitive buffers as soon as
their API boundary allows. Removing this residual limitation would require a
coordinated upstream trait change rather than a fork-only adapter type.

## Future CNSA Boundary

A CNSA-oriented product should be treated as a separate evaluated artifact. The
validated boundary would need to cover the MLS engine, approved cryptographic
module, entropy path, key schedule, secret tree, storage/key wrapping policy,
zeroization, and native FFI surface. Interoperability modes and non-approved
ciphersuites should remain outside that evaluated artifact.

The implemented standards-tracking PQ MLS suites and nonce-proof requirements
are recorded in [PQ_MLS_SUITES.md](PQ_MLS_SUITES.md). They are part of this
fork review only when the `draft-ietf-mls-pq-ciphersuites` feature is explicitly
enabled. Draft review does not turn provisional wire identifiers into final
IANA assignments. Every suite advertised by the ReallyMe provider currently
uses a provisional MLS wire value and is restricted to closed federation.
