---
name: license-busl
description: "FerroAUTH is under the Business Source License 1.1 on the FerroHEALTH terms, Cadasto B.V. the Licensor, Apache 2.0 the Change License four years after each version"
metadata:
  type: project
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

FerroAUTH's own code and text are under the Business Source License 1.1,
the terms FerroBRIDGE, FerroEHR, FerroTERM and FerroUI use. Cadasto B.V. is
the Licensor and handles the business side (info@cadasto.com); the
maintainer handles the technical side.

The Additional Use Grant names authenticating or authorising access to
health data, or issuing or checking tokens for it, through the Licensed
Work; the "issuing" clause predates the decision that the library issues no
token and is the owner's wording to keep or trim.

**How to apply:**

- Every first-party file carries `SPDX-FileCopyrightText: Cadasto B.V.` and
  `SPDX-License-Identifier: BUSL-1.1` in its header;
  `scripts/checks/versions.sh` fails on any other claim.
- `LICENSE` is the one file naming Apache 2.0 as a licence of its own, as the
  Change License.
- Vendored material keeps its upstream terms (CC BY 4.0 for SMART App
  Launch, the IETF Trust Legal Provisions for the RFCs, the OpenID
  Foundation's notice for Discovery), recorded in each `PROVENANCE.md`;
  `deny.toml` admits the dependency licences.
- A contribution is licensed under the same terms (CONTRIBUTING.md §
  Licensing of contributions); opening the pull request accepts them.
