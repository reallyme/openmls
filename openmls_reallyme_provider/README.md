# ReallyMe OpenMLS Provider

`openmls_reallyme_provider` is the narrow cryptography provider for ReallyMe's
OpenMLS fork. It does not change MLS serialization or protocol state. With
`draft-ietf-mls-pq-ciphersuites` enabled, it advertises exactly one suite:

`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`

The provider routes X-Wing-768, ChaCha20-Poly1305, SHA-256, HMAC/HKDF,
Ed25519, and operating-system randomness through ReallyMe Crypto. The X-Wing
KEM is composed with the RFC 9180 key schedule inside this provider because
ReallyMe Crypto 0.2.0 exposes X-Wing and classical HPKE as separate APIs. The
implementation uses HPKE KEM codepoint `0x647a`, matching the existing OpenMLS
libcrux provider.

## Usage

```toml
[dependencies]
openmls = { git = "https://github.com/reallyme/openmls.git", features = ["draft-ietf-mls-pq-ciphersuites"] }
openmls_reallyme_provider = { git = "https://github.com/reallyme/openmls.git", features = ["draft-ietf-mls-pq-ciphersuites"] }
```

```rust
use openmls_reallyme_provider::{Provider, ReallyMeSigner};

let provider = Provider::in_memory();
let signer = ReallyMeSigner::generate()?;
# Ok::<(), openmls_traits::types::CryptoError>(())
```

`Provider<S>` is generic over the OpenMLS storage trait. `in_memory()` matches
the behavior of OpenMLS's existing bundled providers and is useful for tests.
Production applications should inject their audited durable storage with
`Provider::new(storage)`.

The default backend lane is `native`. WASM consumers should disable default
features and enable `wasm` together with the MLS suite feature:

```toml
openmls_reallyme_provider = { git = "https://github.com/reallyme/openmls.git", default-features = false, features = ["wasm", "draft-ietf-mls-pq-ciphersuites"] }
```

The `interop-tests` and `mls-flow-tests` features exist only to validate the
provider in this unpublished fork crate. They are not required by consumers.
