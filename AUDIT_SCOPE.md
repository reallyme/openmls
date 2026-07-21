<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: MIT
-->

# Audit Scope

The current ReallyMe review centers on an OpenMLS provider backed by
`reallyme-crypto`, together with its narrow trait identifier, component
mapping, capability, and bundled-provider isolation changes. It is not, by
itself, a FIPS 140-3 validated cryptographic module or a CNSA 2.0 evaluated MLS
product boundary.

## Current Boundary

In scope for the current ReallyMe provider review:

- supported ciphersuite advertisement;
- ReallyMe-backed AEAD, hash, HKDF/HMAC, Ed25519, P-384 ECDSA, ML-DSA-87,
  X-Wing, and randomness calls;
- provider error mapping;
- feature-gated trait identifiers and component mappings for the reviewed
  suites, plus the explicit capability narrowing in other bundled providers;
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

The provider also relies on the pinned `reallyme-crypto` implementation to
zeroize its typed AEAD and HMAC keys, HPKE contexts, key pairs, and exporter
outputs on drop. That behavior is part of the reviewed dependency boundary:
upgrading `reallyme-crypto` requires revalidating both its zeroization contracts
and the adapter's move-without-clone assumptions.

The enabled ReallyMe facade features are narrower than the transitive build
surface of ReallyMe Crypto 0.3.1. In particular, its monolithic HPKE `native`
feature compiles P-256, P-384, P-521, secp256k1/K-256, X448, ML-KEM, SHAKE, and
TurboSHAKE support even though this provider selects only X-Wing,
ML-KEM-1024, and ML-KEM-1024/P-384 HPKE KEMs. These additional algorithms are
not advertised or selected by the provider, but their source and build scripts
remain inside the dependency review boundary. The locked graph currently
includes `x448 0.14.0-pre.12`, `ed448-goldilocks 0.14.0-pre.15`, `ml-dsa
0.1.1`, `turboshake 0.7.1`, `x-wing 0.1.0`, and
`reallyme-crypto-x-wing 0.3.1`. ReallyMe Crypto should replace the monolithic
HPKE backend feature with component-level features so the provider can compile
only its reviewed KEM, KDF, and AEAD implementations.

Backend failures are intentionally collapsed into fixed OpenMLS error variants.
This prevents key material, plaintext, peer input, or backend-specific details
from reaching logs and FFI error strings. Production observability should count
only the operation class, reviewed suite identifier, and fixed result variant;
it must not attach raw inputs or backend error text.

Provider-boundary primitive KATs include NIST AES-256-GCM and P-384 cases plus
SHA-256 commitments to ML-DSA-87 and ML-KEM-1024 key-generation outputs from
the NIST ACVP Server sample corpus at commit
`15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`. The draft ML-KEM HPKE profiles
also pin deterministic output commitments to detect backend upgrade drift. The
HPKE-PQ working group's `test-vectors.json` at commit
`11b5b9541e9976fc9ce25902011d20dacc089066` (file SHA-256
`35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c`)
independently covers the exact ML-KEM-1024/HKDF-SHA384/AES-256-GCM and
ML-KEM-1024+P-384/HKDF-SHA384/AES-256-GCM production profiles. Separate fixed
input commitments remain as backend-upgrade regression evidence.

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
