# Fork Policy

ReallyMe keeps this fork close to upstream OpenMLS and limits changes to the
smallest surface needed for the ReallyMe provider and post-quantum
ciphersuites.

Changes outside the fork points below should preserve upstream behavior unless
there is a specific, documented reason to diverge.

## Fork Points

| Area | Files |
|---|---|
| ReallyMe provider | `openmls_reallyme_provider` |
| PQ ciphersuite types | `traits/src/types.rs` |
| Unsupported-suite rejection | `openmls_rust_crypto`, `libcrux_crypto` |
| Provider-derived defaults | `openmls/src/group/mls_group/builder.rs`, `openmls/src/group/mls_group/config.rs`, `openmls/src/key_packages/mod.rs` |
| External-join defaults | `openmls/src/group/mls_group/creation.rs`, `openmls/src/group/public_group/diff/compute_path.rs` |
| ReallyMe provider CI | `.github/workflows/reallyme_provider.yml` |
| Workspace dependency policy | `Cargo.toml`, `Cargo.lock`, `deny.toml`, member `Cargo.toml` files |
| Development toolchain | `rust-toolchain.toml` |

The PQ fork point contains the feature-gated KEM and ciphersuite mappings
documented in [PQ_MLS_SUITES.md](PQ_MLS_SUITES.md).

Provider-derived defaults apply only when the caller does not provide explicit
capabilities.

## Upstream Sync

Merge upstream changes rather than rewriting published ReallyMe history.

```sh
git fetch upstream
git log --oneline --left-right main...upstream/main
git merge --no-ff upstream/main
```

When resolving conflicts, preserve upstream behavior outside the documented
fork points.

Changes touching ciphersuites, HPKE, provider traits, storage, credentials,
serialization, or capability handling require particular review. Run the
applicable [RELEASE.md](RELEASE.md) checks before merging.

## Adding A Fork Point

New ReallyMe-specific changes should prefer provider crates, feature gates, and
small explicit fork points over broad changes to OpenMLS protocol code.

Add new fork points here when they introduce a persistent divergence from
upstream. Document the affected area and link to any protocol, compatibility,
or release requirements that explain the change.
