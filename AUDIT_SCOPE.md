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
- HPKE bridge behavior for the supported X-Wing ciphersuite;
- provider interoperability and MLS flow tests.

Outside the current provider boundary:

- OpenMLS core key schedule and group state internals;
- application identity, credential, and authorization policy;
- durable storage implementations supplied by production applications;
- Swift, Kotlin, Java, TypeScript, WASM, JNI, or C ABI adapters not present in
  this repository;
- FIPS 140-3, NIAP, CSfC, or CNSA product evaluation claims.

## Future CNSA Boundary

A CNSA-oriented product should be treated as a separate evaluated artifact. The
validated boundary would need to cover the MLS engine, approved cryptographic
module, entropy path, key schedule, secret tree, storage/key wrapping policy,
zeroization, and native FFI surface. Interoperability modes and non-approved
ciphersuites should remain outside that evaluated artifact.
