<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: MIT
-->

# Release Policy

ReallyMe releases of this fork must be reproducible, reviewable, and explicit
about their upstream base. Release notes should name the upstream OpenMLS commit
or tag, the ReallyMe fork commit, the supported ciphersuites, and the exact
`reallyme-crypto` version used by the ReallyMe provider.

A release candidate must be a committed revision with a clean worktree. Record
the resulting commit identifier with the validation evidence so binaries,
vectors, and dependency review remain reproducible:

```sh
test -z "$(git status --porcelain)"
git rev-parse HEAD
```

## Required Checks

Run the relevant workspace gates before a release candidate:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
CARGO_PROFILE_TEST_DEBUG=0 cargo test --workspace --all-features --locked -- --test-threads=1
cargo deny --manifest-path openmls_reallyme_provider/Cargo.toml \
  --features extensions-draft,draft-ietf-mls-pq-ciphersuites,targeted-messages-draft,virtual-clients-draft \
  --locked check --exclude-dev --deny warnings
cargo build -p openmls_reallyme_provider --release --features draft-ietf-mls-pq-ciphersuites --locked
cargo test -p openmls_reallyme_provider --all-features --locked
cargo test -p openmls --lib --features reallyme-provider --locked -- --test-threads=1
```

Provider releases must also run focused ReallyMe interoperability and MLS flow
tests for each supported ciphersuite. Dependency upgrades that affect crypto,
serialization, storage, credentials, or FFI require release notes explaining the
review and test evidence.

The release build deliberately omits `test-utils`: this proves that the normal
provider surface requires caller-supplied storage and does not expose the
dev-only deterministic vector API.

The deny gate is rooted at the maximal deployable ReallyMe provider graph and
excludes development dependencies. `--all-features` is intentionally not used
for this command because it activates the `interop-tests`, `mls-flow-tests`, and
`test-utils` adapters that cannot enter a production artifact. Those adapters
remain covered by the compile, Clippy, and test gates. Upstream's optional
interop client currently pulls `mls_interop_proto` from a Git repository whose
crate manifest declares no license; that tool is not part of the production
artifact and must not be redistributed unless its upstream licensing is
clarified. Do not weaken the provider graph's license gate to accommodate it.
Running `cargo deny check` at the workspace root is therefore not the release
gate and includes upstream demonstration, test, and interoperability tooling
that is deliberately outside the deployable provider graph.

The pinned ReallyMe HPKE backend currently brings `x448 0.14.0-pre.12` into the
native production dependency graph. The provider's exact HPKE suite mapping
does not expose X448, but ReallyMe Crypto 0.3.1 enables it as part of its
monolithic native HPKE backend feature. Treat this pre-release transitive crate
as a release residual risk, keep it lockfile-pinned, and remove it when the
backend offers a narrower feature or migrates to a stable X448 release.

The facade's exact `reallyme-crypto =0.3.1` requirement does not make its
published first-party sub-crate requirements exact. The committed lockfile and
every fork CI/release command therefore use `--locked`. A ReallyMe Crypto
release should additionally pin its coordinated internal crates with exact
requirements so regenerating this lockfile cannot silently mix patch releases
from different reviewed publication sets.

Before a public production release, document and review the publishing controls
for every ReallyMe Crypto crate used by this provider. Prefer crates.io Trusted
Publishing from a protected release environment when the publishing workflow
supports it. The number of crate owners is an operational risk decision: an
additional owner can improve recovery while also expanding the account
compromise surface, so this repository does not prescribe a minimum. Record the
publisher or workflow identity, crate versions, and lockfile checksum with the
release evidence.

Binary distributions must ship notices for the exact locked production graph.
The repository notice file records the non-default BSD and Unicode terms known
to be present, but release packaging must regenerate and compare a complete
notice bundle after every lockfile change.

The workspace test gate is intentionally single-threaded. The all-provider,
all-ciphersuite test binary can exceed ordinary CI memory limits when Rust runs
many large post-quantum test cases concurrently; a SIGKILL is not a passing
security or correctness result.

## Draft-suite deployment gate

The standards-tracking PQ suites remain an IETF draft, and none of the four
ReallyMe provider suites has a final IANA MLS ciphersuite assignment. Three
compatibility values are currently unassigned in the MLS registry; the hybrid
suite uses a private-use codepoint. They may be enabled only in a closed
deployment where every peer pins the same reviewed fork revision and suite
registry. Do not advertise these codepoints on an open federation or claim
final IANA interoperability. Re-review the wire identifiers and vectors before
replacing any provisional value with an IANA assignment.

## Dependency Pinning

The ReallyMe provider pins `reallyme-crypto` exactly because cryptographic
behavior is part of the reviewed provider surface. Upgrading that dependency is
a release event, not routine dependency hygiene.

## Publishing

ReallyMe-only fork crates use `publish = false` unless ReallyMe explicitly
decides to publish a public package. Internal production consumers should pin
the reviewed Git revision or release tag.
