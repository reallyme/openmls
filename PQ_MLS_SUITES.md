<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: MIT
-->

# PQ MLS Suite Support

This note records the standards-tracking post-quantum MLS suites supported by
the ReallyMe OpenMLS fork. It is intentionally narrow: ReallyMe only advertises
the suites that are wired to `reallyme-crypto`, covered by provider tests, and
reviewed as part of the fork boundary.

The current reference is `draft-ietf-mls-pq-ciphersuites-05`, published
2026-07-02:

<https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/>

## Supported Suites

ReallyMe supports these draft MLS ciphersuite families in addition to the
deployed X-Wing-768 compatibility suite
`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`:

1. `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`

   This is the CNSA-oriented pure post-quantum candidate profile. It is not a
   validated or evaluated product boundary. The draft maps it to:

   - HPKE KEM: `0x0042` ML-KEM-1024
   - HPKE KDF: `0x0011` SHAKE256, `Nh = 64`
   - HPKE AEAD: `0x0002` AES-256-GCM
   - MLS hash: SHA-384
   - Signature: ML-DSA-87

2. `MLS_192_MLKEM1024_AES256GCM_SHA384_P384`

   This is the pure ML-KEM-1024 KEM suite with traditional P-384 signatures.
   It is useful when deployments want NIST post-quantum key establishment
   while retaining traditional P-384 authentication. The draft maps it to:

   - HPKE KEM: `0x0042` ML-KEM-1024
   - HPKE KDF: `0x0011` SHAKE256, `Nh = 64`
   - HPKE AEAD: `0x0002` AES-256-GCM
   - MLS hash: SHA-384
   - Signature: ECDSA secp384r1 SHA-384

3. `MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384`

   This is the NIST PQ/traditional hybrid KEM transition target. The draft
   maps it to:

   - HPKE KEM: `0x0051` ML-KEM-1024 + P-384
   - HPKE KDF: `0x0011` SHAKE256, `Nh = 64`
   - HPKE AEAD: `0x0002` AES-256-GCM
   - MLS hash: SHA-384
   - Signature: ECDSA secp384r1 SHA-384

## OpenMLS Fork Point

The fork carries the minimal trait/type additions required by the current MLS
PQ draft:

- HPKE KDF `0x0011` SHAKE256;
- HPKE KEM `0x0051` ML-KEM-1024 + P-384;
- keep HPKE AEAD `0x0002` as ordinary AES-256-GCM, not AES-GCM-SIV;
- map the draft SHA-384 ML-KEM suites to SHAKE256 HPKE KDF values;
- advertise only the ReallyMe-reviewed suites from the ReallyMe provider.

None of the four ReallyMe provider suites has a final IANA MLS ciphersuite
assignment. Their current wire values are:

- X-Wing compatibility suite: `0x004D` (currently unassigned by IANA);
- ML-KEM-1024 with P-384 signatures: `0x0042` (currently unassigned by IANA);
- ML-KEM-1024 with ML-DSA-87: `0x0907` (currently unassigned by IANA);
- hybrid ML-KEM-1024/P-384: `0xF043` (IANA private-use range).

The first three values are inherited compatibility points from the upstream
draft implementation. The hybrid value was deliberately selected from the MLS
private-use range because the draft still marks it as TBD5. Replace these values
only through a versioned group-state migration after final assignments exist.

These provisional values are a production interoperability boundary, not
merely a documentation detail. They must only be deployed in a closed
federation whose members pin the same fork revision. They must not be offered
to arbitrary public MLS peers, persisted without a registry-version migration
plan, or described as IANA-assigned suites.

## `reallyme-crypto` Boundary

The OpenMLS provider delegates base HPKE, exporter operations, AES-256-GCM,
SHA-384, P-384 signatures, and ML-DSA-87 signatures to `reallyme-crypto`.
ReallyMe Crypto v0.3.1 exposes the required suite components:

Required HPKE support:

- `HpkeKemId::MlKem1024 = 0x0042`
- `HpkeKemId::MlKem1024P384 = 0x0051`
- `HpkeKdfId::Shake256 = 0x0011`
- `HpkeAeadId::Aes256Gcm = 0x0002`
- base-mode seal/open;
- deterministic key derivation from IKM;
- sender/receiver exporter APIs;
- split PSK sender/receiver setup for OpenMLS targeted-message AAD binding;
- deterministic test-vector mode for KEM randomness.

OpenMLS builds targeted-message authenticated data from the encapsulated key, so
the provider uses ReallyMe Crypto's split PSK sender setup: create the KEM
output first, build AAD, then seal with the returned opaque context.

Required MLS primitive support:

- SHA-384 digest;
- HMAC-SHA384;
- HKDF-SHA384 extract/expand;
- AES-256-GCM encrypt/decrypt with 32-byte key, 12-byte nonce, 16-byte tag;
- ML-DSA-87 key generation, sign, and verify;
- P-384 SHA-384 ECDSA key generation, sign, and verify.

## Nonce Proof Requirements

AES-256-GCM is acceptable for the standards-facing suites only if nonce
uniqueness remains protocol-derived and test-covered. ReallyMe Crypto should
validate key, nonce, and tag lengths. It should not generate random MLS/HPKE
nonces for these suites.

Provider and MLS tests should continue proving:

- HPKE derives 12-byte AES-GCM nonces internally;
- repeated base-mode seals to the same recipient differ when encapsulation
  randomness differs;
- deterministic HPKE vector mode is stable with fixed KEM randomness;
- OpenMLS application messages in one epoch do not reuse `(key, nonce)` pairs;
- handshake and application encryption contexts do not reuse `(key, nonce)`
  pairs;
- epoch transitions change encryption secrets;
- tampered `enc`, AAD, info, ciphertext, or tag fails closed.

The ReallyMe provider copies the deterministic test inputs used by ReallyMe
Crypto through a dev-only dependency. Deterministic KEM entry points are not a
downstream-selectable provider feature and cannot be enabled by a normal
production dependency. These are regression vectors from the pinned backend,
not independent third-party conformance evidence. X-Wing retains a separate
cross-provider libcrux interoperability test.

## Production checklist

Before deploying a reviewed revision:

- enable only the suite feature set required by the deployment;
- construct group and key-package capabilities with
  `Capabilities::for_provider(provider.crypto())` so leaves advertise only
  executable ReallyMe suites;
- use caller-supplied durable storage; the in-memory provider API is compiled
  only under `test-utils`;
- pin this repository revision and the exact `reallyme-crypto` release;
- run the release gates in [RELEASE.md](RELEASE.md), including all four MLS
  flows and the advisory check;
- record the provisional suite registry version alongside persisted group
  state and define the migration behavior for final IANA codepoints;
- keep credentials, authorization, backup/key wrapping, telemetry redaction,
  and compromise recovery in the application security boundary.

## Out Of Scope

Do not introduce AES-256-GCM-SIV into the standards-facing HPKE/MLS suites.
There is no registered HPKE AEAD identifier for AES-GCM-SIV, and using it would
make the suite private rather than standards-tracking.
