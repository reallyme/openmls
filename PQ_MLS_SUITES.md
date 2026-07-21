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

   This is the CNSA-facing pure post-quantum target. The draft maps it to:

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

The hybrid MLKEM1024-P384 MLS ciphersuite still uses a ReallyMe private
provisional codepoint (`0xF043`) because the draft marks that MLS ciphersuite
identifier as TBD. Replace it with the final IANA assignment when the draft
stabilizes.

## `reallyme-crypto` Boundary

The OpenMLS provider delegates base HPKE, exporter operations, AES-256-GCM,
SHA-384, P-384 signatures, and ML-DSA-87 signatures to `reallyme-crypto`.
ReallyMe Crypto v0.3.0 exposes the required suite components:

Required HPKE support:

- `HpkeKemId::MlKem1024 = 0x0042`
- `HpkeKemId::MlKem1024P384 = 0x0051`
- `HpkeKdfId::Shake256 = 0x0011`
- `HpkeAeadId::Aes256Gcm = 0x0002`
- base-mode seal/open;
- deterministic key derivation from IKM;
- sender/receiver exporter APIs;
- deterministic test-vector mode for KEM randomness.

The remaining local bridge is targeted-message PSK setup for the deployed
X-Wing suite. OpenMLS builds the authenticated data from the encapsulated key,
so it needs split sender setup: create the KEM output first, build AAD, then
seal. Once `reallyme-crypto` exposes split PSK sender/receiver contexts, this
local bridge should be removed.

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

## Out Of Scope

Do not introduce AES-256-GCM-SIV into the standards-facing HPKE/MLS suites.
There is no registered HPKE AEAD identifier for AES-GCM-SIV, and using it would
make the suite private rather than standards-tracking.
