<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: MIT
-->

# ReallyMe OpenMLS Provider

`openmls_reallyme_provider` is the narrow cryptography provider for ReallyMe's
OpenMLS fork. It does not change MLS serialization or protocol state. With
`draft-ietf-mls-pq-ciphersuites` enabled, it advertises:

- `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`;
- `MLS_192_MLKEM1024_AES256GCM_SHA384_P384`;
- `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`;
- `MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384`.

The provider delegates the supported base and PSK HPKE operations, exporter
operations, AEAD, hashes, signatures, and randomness to ReallyMe Crypto 0.3.1.
The dependency is exactly pinned because changing the cryptographic backend is
a reviewed release event. All four MLS wire identifiers are provisional; their
different registry statuses are documented in
[PQ_MLS_SUITES.md](../PQ_MLS_SUITES.md).

## Usage

```toml
[dependencies]
openmls = { git = "https://github.com/reallyme/openmls.git", rev = "<reviewed-commit>", features = ["draft-ietf-mls-pq-ciphersuites"] }
openmls_reallyme_provider = { git = "https://github.com/reallyme/openmls.git", rev = "<reviewed-commit>", features = ["draft-ietf-mls-pq-ciphersuites"] }
```

```rust
use openmls::prelude::{
    Capabilities, Ciphersuite, MlsGroupCreateConfig, OpenMlsProvider as _,
};
use openmls_reallyme_provider::{Provider, ReallyMeSuiteSigner};

let storage = AuditedDurableStorage::open()?;
let provider = Provider::new(storage);
let suite = Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384;
let signer = ReallyMeSuiteSigner::generate(suite.signature_algorithm())?;
let group_config = MlsGroupCreateConfig::builder()
    .ciphersuite(suite)
    .capabilities(Capabilities::for_provider(provider.crypto()))
    .build();
```

`Provider<S>` is generic over the OpenMLS storage trait. Production applications
must inject their audited durable storage with `Provider::new(storage)`.
`MemoryStorage`, `Provider::in_memory()`, and its `Default` implementation are
available only with `test-utils`; normal builds cannot select ephemeral storage
by accident.

Use `Capabilities::for_provider(provider.crypto())` for group configurations
and key packages. Global OpenMLS defaults cover suites from several providers;
advertising them unchanged would claim support for algorithms this narrow
provider intentionally rejects. `ReallyMeSigner` is Ed25519-only and is
appropriate for the X-Wing compatibility suite. Use `ReallyMeSuiteSigner` with
the selected suite's signature algorithm for P-384 and ML-DSA-87 suites.

Production consumers must replace `<reviewed-commit>` with the same immutable
fork revision for both crates. Following the moving `main` branch is not a
reproducible deployment policy.

The default backend lane is `native`. WASM consumers should disable default
features and enable `wasm` together with the MLS suite feature:

```toml
openmls_reallyme_provider = { git = "https://github.com/reallyme/openmls.git", rev = "<reviewed-commit>", default-features = false, features = ["wasm", "draft-ietf-mls-pq-ciphersuites"] }
```

Disabling default features without selecting `wasm` is not a supported
configuration in ReallyMe Crypto 0.3.1 and does not produce a provider artifact.

The `interop-tests` and `mls-flow-tests` features exist only to validate the
provider in this unpublished fork crate. Deterministic backend vector APIs are
confined to a dev dependency and are not selectable by consumers.
