# Release Policy

ReallyMe releases of this fork must be reproducible, reviewable, and explicit
about their upstream base. A release note names the upstream OpenMLS commit or
tag, the ReallyMe fork commit, the supported ciphersuites, and the exact
`reallyme-crypto` version used by the provider.

A release candidate is a committed revision with a clean worktree:

```sh
test -z "$(git status --porcelain)"
git rev-parse HEAD
```

Record the commit identifier with the validation evidence. Binaries,
conformance vectors, dependency review, and notices should all resolve back to
that same revision.

## Required Gates

Run the gates that match the release scope. Provider releases must include the
provider and OpenMLS corpus checks below. Run the sync workspace and the async
test workspace separately because Cargo unifies the storage trait features
within each build and the SQLite provider requires sync traits.

```sh
cargo fmt --all -- --check
sync_features=$(cargo metadata --locked --no-deps --format-version 1 | jq -r \
  '.packages[] | .name as $p | .features | del(.async) | keys[] | "\($p)/\(.)"')
test_features=$(printf '%s\n' "$sync_features" | grep -vxE \
  'openmls/generate-kats|openmls_libcrux_crypto/legacy-pq-key-derivation')
cargo check --workspace --features "$sync_features" --locked
cargo clippy --workspace --all-targets --features "$sync_features" --locked -- -D warnings
CARGO_PROFILE_TEST_DEBUG=0 cargo test --workspace --features "$test_features" --locked -- --test-threads=1
cargo test -p openmls_libcrux_crypto --features legacy-pq-key-derivation --locked
cargo clippy --manifest-path openmls_async_tests/Cargo.toml --all-targets --all-features --locked -- -D warnings
cargo test --manifest-path openmls_async_tests/Cargo.toml --all-features --locked
cargo deny --manifest-path openmls_reallyme_provider/Cargo.toml \
  --features extensions-draft,draft-ietf-mls-pq-ciphersuites,targeted-messages-draft,virtual-clients-draft \
  --locked --exclude-dev check --deny warnings
cargo build -p openmls_reallyme_provider --release --features draft-ietf-mls-pq-ciphersuites --locked
cargo test -p openmls_reallyme_provider --all-features --locked
cargo test -p openmls --lib --features reallyme-provider --locked -- --test-threads=1
```

The test run excludes the vector generators so it validates the checked-in
fixtures. Run the legacy libcrux derivation in its own test lane because it
intentionally derives different X-Wing keys from the current provider.
The workspace test gate is intentionally single-threaded. The all-provider,
all-ciphersuite test binary can exceed ordinary CI memory limits when Rust runs
many post-quantum test cases concurrently; a SIGKILL is not a passing result.

## Provider Graph

The deployable provider graph is rooted at
`openmls_reallyme_provider/Cargo.toml` and excludes development dependencies.
Do not use `--all-features` for the `cargo deny` release gate: that would enable
`interop-tests`, `mls-flow-tests`, and `test-utils`, which are test adapters,
not production inputs.

The ReallyMe Crypto 0.4.0 configuration enables the following HPKE components:
ML-KEM-768, ML-KEM-1024, ML-KEM-1024/P-384, X-Wing, HKDF-SHA256,
HKDF-SHA384, AES-256-GCM, and ChaCha20-Poly1305 where required. Release checks
must show that the production graph contains only those HPKE components, does
not expose deterministic test-vector APIs, and uses exactly version 0.4.0 for
every `reallyme-crypto` crate.

The 0.4.0 protobuf runtime pins ReallyMe Buffa 0.1.1. Its JSON support requires
`base64` 0.22.1, while Crypto and Codec use 0.23.1. The provider audit allows
that exact duplicate and the Zlib license of Buffa's `foldhash` 0.1.5 dependency.
Focused interoperability, large-context, and generic external-join regressions
must pass against the registry dependency before changing the baseline.

## Draft Suites

The standards-tracking PQ suites remain IETF draft material. The seven ReallyMe
provider suites use the provisional and compatibility values documented in
[PQ_MLS_SUITES.md](PQ_MLS_SUITES.md).

Enable these suites only when every participating implementation pins the same
fork revision and suite registry. Do not advertise them to arbitrary public MLS
peers, and do not describe them as IANA-assigned. Re-review wire identifiers
and vectors before replacing any provisional value with a final assignment.

## Dependency Changes

The provider pins `reallyme-crypto` exactly because cryptographic behavior is
part of the reviewed surface. Upgrading that dependency is a release event. The
release evidence should explain the change, include focused interoperability
and MLS-flow results for every supported ciphersuite, and identify any affected
serialization, storage, credential, or FFI boundary.

Before a public production release, review the publishing controls for every
ReallyMe Crypto crate used by the provider. Record the publisher or trusted
publishing workflow identity, crate versions, and lockfile checksums.

## Historical Compatibility Fixtures

`compat_tests` deliberately locks historical OpenMLS 0.7.4 and 0.8.1
credential providers so storage migrations remain executable. Those providers
depend on `p256` 0.13.2 and therefore `crypto-bigint` 0.5.5, which is affected
by RUSTSEC-2026-0387. No patched `crypto-bigint` release satisfies that
historical dependency graph.

This exception is limited to the unpublished, workspace-excluded migration
test crate. It must not enter a production dependency graph, release artifact,
or deployed binary. The provider-rooted `cargo deny` gate and the current-code
lockfiles must remain free of the advisory. Re-evaluate the fixture when the
historical migration inputs can be generated without executing the old
credential providers.

## Notices And Publishing

Binary distributions must ship notices for the exact locked production graph.
`THIRD_PARTY_NOTICES.md` records the non-default BSD and Unicode terms known in
this repository, but release packaging must regenerate and compare a complete
notice bundle after every lockfile change.

ReallyMe-only fork crates use `publish = false` unless ReallyMe explicitly
decides to publish a public package. Internal production consumers should pin
the reviewed Git revision or release tag.
