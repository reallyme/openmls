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
provider and OpenMLS corpus checks below.

```sh
cargo fmt --all -- --check
cargo check --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
CARGO_PROFILE_TEST_DEBUG=0 cargo test --workspace --all-features --locked -- --test-threads=1
cargo deny --manifest-path openmls_reallyme_provider/Cargo.toml \
  --features extensions-draft,draft-ietf-mls-pq-ciphersuites,targeted-messages-draft,virtual-clients-draft \
  --locked --exclude-dev check --deny warnings
cargo build -p openmls_reallyme_provider --release --features draft-ietf-mls-pq-ciphersuites --locked
cargo test -p openmls_reallyme_provider --all-features --locked
cargo test -p openmls --lib --features reallyme-provider --locked -- --test-threads=1
```

The workspace test gate is intentionally single-threaded. The all-provider,
all-ciphersuite test binary can exceed ordinary CI memory limits when Rust runs
many post-quantum test cases concurrently; a SIGKILL is not a passing result.

## Provider Graph

The deployable provider graph is rooted at
`openmls_reallyme_provider/Cargo.toml` and excludes development dependencies.
Do not use `--all-features` for the `cargo deny` release gate: that would enable
`interop-tests`, `mls-flow-tests`, and `test-utils`, which are test adapters,
not production inputs.

ReallyMe Crypto 0.3.9 exposes only the HPKE components this provider needs:
ML-KEM-768, ML-KEM-1024, ML-KEM-1024/P-384, X-Wing, HKDF-SHA256,
HKDF-SHA384, AES-256-GCM, and ChaCha20-Poly1305 where required. Release checks
must show that the production graph contains only those HPKE components, does
not expose deterministic test-vector APIs, and uses a single `reallyme-crypto`
patch version.

The 0.3.9 upgrade retains the HPKE input validation from 0.3.8 and adds the
ML-KEM-768/HKDF-SHA384 and X-Wing/HKDF-SHA384 suite compositions used by the
newer provider suites. Large-context and generic external-join regressions must
pass against the registry dependency.

## Draft Suites

The standards-tracking PQ suites remain IETF draft material. None of the six
ReallyMe provider suites has a final IANA MLS ciphersuite assignment. Five
values occupy currently unassigned registry space; the ML-KEM-1024/P-384
hybrid suite uses a private-use value.

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

## Notices And Publishing

Binary distributions must ship notices for the exact locked production graph.
`THIRD_PARTY_NOTICES.md` records the non-default BSD and Unicode terms known in
this repository, but release packaging must regenerate and compare a complete
notice bundle after every lockfile change.

ReallyMe-only fork crates use `publish = false` unless ReallyMe explicitly
decides to publish a public package. Internal production consumers should pin
the reviewed Git revision or release tag.
