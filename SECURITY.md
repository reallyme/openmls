# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/reallyme/openmls/security/advisories/new)
or by email to **security@really.me**.

Do not open a public issue, pull request, or discussion for a suspected
vulnerability.

Include enough information to reproduce and assess the issue, including the
affected version or commit, platform, and ciphersuite where relevant. Do not
include private keys, plaintext messages, production MLS state, or personal
information.

## Scope

Security issues in the ReallyMe OpenMLS fork and
`openmls_reallyme_provider` can be reported here.

Issues in the underlying [`reallyme-crypto`](https://github.com/reallyme/crypto)
implementation should be reported through
[that repository's private vulnerability reporting](https://github.com/reallyme/crypto/security/advisories/new)
or by email to **security@really.me**. If an issue in `reallyme-crypto` causes a
vulnerability through the OpenMLS provider, it may also be reported here.

## Supported Versions

ReallyMe deployments should pin a specific release or Git revision. Security
fixes are made against the currently maintained version of the fork; older
revisions may require upgrading to receive a fix.

## Disclosure

Please allow us reasonable time to investigate and release a fix before public
disclosure. We are happy to credit reporters in the resulting advisory or
release notes unless they prefer to remain anonymous.
