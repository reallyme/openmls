# Post-Quantum MLS Ciphersuites

This fork implements five ciphersuites from
[draft-ietf-mls-pq-ciphersuites-06](https://datatracker.ietf.org/doc/html/draft-ietf-mls-pq-ciphersuites-06)
and retains one X-Wing ciphersuite for compatibility with existing deployments.

## Ciphersuites

| Suite | MLS wire | KEM | KDF | AEAD / Hash | Signature |
|---|---:|---|---|---|---|
| `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` | `0x004D` | X-Wing (ML-KEM-768 + X25519) | HKDF-SHA256 | ChaCha20-Poly1305 / SHA-256 | Ed25519 |
| `MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519` | `0x004E` | ML-KEM-768 + X25519 | HKDF-SHA384 | AES-256-GCM / SHA-384 | Ed25519 |
| `MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65` | `0x0051` | ML-KEM-768 | HKDF-SHA384 | AES-256-GCM / SHA-384 | ML-DSA-65 |
| `MLS_192_MLKEM1024_AES256GCM_SHA384_P384` | `0x0042` | ML-KEM-1024 | HKDF-SHA384 | AES-256-GCM / SHA-384 | P-384 ECDSA |
| `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87` | `0x0907` | ML-KEM-1024 | HKDF-SHA384 | AES-256-GCM / SHA-384 | ML-DSA-87 |
| `MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384` | `0xF043` | ML-KEM-1024 + P-384 | HKDF-SHA384 | AES-256-GCM / SHA-384 | P-384 ECDSA |

## Draft Mapping

The fork currently tracks draft-06.

The relevant HPKE assignments are:

| Component | ID |
|---|---:|
| ML-KEM-768 | `0x0041` |
| ML-KEM-1024 | `0x0042` |
| ML-KEM-1024 + P-384 | `0x0051` |
| ML-KEM-768 + X25519 | `0x647A` |
| HKDF-SHA384 | `0x0002` |
| AES-256-GCM | `0x0002` |

Draft-05 used single-stage SHAKE256 KDFs for some mappings. Draft-06 uses HKDF
to provide the Extract and Expand operations required by MLS.

Groups created with the draft-05 SHAKE mapping are not compatible with the
draft-06 HKDF mapping, even where the provisional MLS ciphersuite identifier is
unchanged. The provider does not attempt KDF fallback.

## Provisional MLS Codepoints

None of these ciphersuites has a final IANA MLS assignment.

| Suite | Current value | Status |
|---|---:|---|
| X-Wing compatibility | `0x004D` | unassigned |
| ML-KEM-768/X25519 | `0x004E` | unassigned |
| ML-KEM-768/ML-DSA-65 | `0x0051` | unassigned |
| ML-KEM-1024/P-384 signature | `0x0042` | unassigned |
| ML-KEM-1024/ML-DSA-87 | `0x0907` | unassigned |
| ML-KEM-1024/P-384 hybrid | `0xF043` | private use |

Until final assignments are available, communicating implementations must use
the same ciphersuite mappings. Do not silently remap an existing identifier
when the draft or IANA registry changes; existing groups must retain the
mapping under which they were created or migrate to a new group.

## ReallyMe Crypto

`openmls_reallyme_provider` uses `reallyme-crypto` for the cryptographic
operations required by these suites.

Required HPKE support:

- ML-KEM-768
- ML-KEM-1024
- ML-KEM-1024 + P-384
- ML-KEM-768 + X25519
- HKDF-SHA256 and HKDF-SHA384
- ChaCha20-Poly1305 and AES-256-GCM
- base-mode seal/open
- deterministic key derivation from IKM
- sender and receiver exporter APIs
- split PSK sender/receiver setup

Required MLS primitives:

- SHA-256 and SHA-384
- HMAC and HKDF
- ChaCha20-Poly1305 and AES-256-GCM
- Ed25519
- P-384 ECDSA with SHA-384
- ML-DSA-65
- ML-DSA-87

OpenMLS constructs targeted-message authenticated data using the encapsulated
key. The provider therefore uses the split PSK sender API: produce the KEM
output first, construct the AAD, then seal using the returned context.

## Nonces and Test Vectors

AES-GCM nonces are derived by HPKE and MLS; the provider does not generate
random nonces for these operations.

Tests cover:

- 12-byte AES-GCM nonce derivation;
- randomized HPKE encapsulation;
- deterministic HPKE vectors with fixed KEM randomness;
- nonce uniqueness across application, handshake, and epoch transitions;
- rejection of modified encapsulated keys, AAD, info, ciphertext, and tags.

Deterministic test inputs are available only through development dependencies
and are not exposed by production builds.

## Deployment

Pin both this fork and `reallyme-crypto` to the revisions used to create the
group. When a draft changes the cryptographic mapping or provisional
ciphersuite identifier, treat it as an interoperability change rather than
silently changing existing groups.

Run the release checks in [RELEASE.md](RELEASE.md) before deploying a new
revision.
