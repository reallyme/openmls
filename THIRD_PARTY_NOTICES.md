<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: MIT
-->

# Third-Party Notices

This repository is based on OpenMLS.

OpenMLS upstream:

- Repository: <https://github.com/openmls/openmls>
- License: MIT
- Copyright: OpenMLS Authors

ReallyMe Crypto is an external dependency of the ReallyMe provider.

- Repository: <https://github.com/reallyme/crypto>
- License: Apache-2.0
- Copyright: ReallyMe LLC

External repositories and dependencies keep their own licenses. This repository
does not relicense linked dependencies or separately distributed packages.

The upstream-only `interop_client` development tool fetches
`mls_interop_proto` from the MLS working-group implementations repository. That
crate currently has no license expression or license file in its pinned source.
It is excluded from the ReallyMe production artifact and must not be
redistributed until its upstream licensing is clarified.
