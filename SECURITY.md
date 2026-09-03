<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: MIT
-->

# Security Policy

This fork is security-sensitive infrastructure built on OpenMLS, an
implementation of the Messaging Layer Security protocol defined by RFC 9420.
We treat MLS state-machine bugs, provider divergence, unsupported ciphersuite
negotiation, downgrade acceptance, key-material exposure, storage-boundary
mistakes, and dependency drift as security-relevant.

## Reporting

Please report suspected vulnerabilities privately before public disclosure.
Use [GitHub private vulnerability reporting](https://github.com/reallyme/openmls/security/advisories/new)
for this repository when available; otherwise email **security@really.me**. Do
not open a public issue, pull request, or discussion for a suspected
vulnerability.

Include the affected crate, version or commit, ciphersuite, platform, and the
smallest reproduction you can share without exposing private keys, plaintext
messages, production group state, or personally identifiable information.
Describe the observed behavior, its security impact, and the MLS guarantee it
may violate.

## Threat Model

We evaluate reports against the MLS threat model described in RFC 9420. Assume
an adversary that can observe, drop, reorder, replay, and inject network traffic
and can control the delivery service that relays messages.

## In Scope

The coordinated-disclosure scope covers the `openmls` crate and ReallyMe's
fork-specific provider, trait, storage, and integration changes. In particular:

- violations of confidentiality, authenticity, group key agreement, forward
  secrecy, or post-compromise security;
- panics, aborts, or unbounded resource consumption reachable through
  unauthenticated attacker-controlled input;
- ReallyMe provider behavior that diverges from the reviewed OpenMLS provider
  contract;
- acceptance of unsupported ciphersuites or unexpected downgrade paths;
- leakage of raw key material, plaintext, credentials, or backend exception
  text through errors, logs, FFI, or test fixtures;
- storage-boundary errors that disclose, orphan, or corrupt MLS state; and
- dependency upgrades that alter cryptographic behavior without updated tests.

If you are unsure whether a finding qualifies, report it privately and let us
assess it.

## Out of Scope

- Application bugs outside this repository.
- Attacks that require breaking an underlying cryptographic primitive.
- Metadata exposure that RFC 9420 permits by design.
- Panics or incorrect results reachable only when a caller violates a clearly
  documented API precondition.
- Unsupported feature or platform combinations that cannot produce a release
  artifact.
- Experimental ciphersuites or draft features not documented as production
  surfaces.

Primitive implementation bugs in the separate `reallyme-crypto` repository
should be reported through that repository's private security channel. If the
issue is observable through this fork's provider boundary, it remains in scope
here as an integration vulnerability.

## Supported Versions

This fork is pre-1.0 from ReallyMe's perspective. Production deployments must
pin an exact Git revision, release tag, or package version and consume only the
ReallyMe-supported provider and ciphersuite surfaces documented in this
repository.

## Good-Faith Research and Recognition

We will not pursue or support action against anyone who reports a vulnerability
in good faith under this policy, provided they avoid privacy violations, data
destruction, and disruption of other users and allow a reasonable opportunity
to publish a fix before disclosure. With the reporter's agreement, we will
credit them in the advisory or release notes; anonymous reporting is welcome.
