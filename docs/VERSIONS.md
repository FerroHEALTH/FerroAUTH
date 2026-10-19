<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Pinned version matrix

This file is the single source of truth for every version pin in FerroSMART.
When it and a file that repeats a pin disagree, that is drift. Fix the
disagreement; never let either side silently win. `scripts/checks/versions.sh`
reads every vendored `PROVENANCE.md` and every vendored file back against the
rows below.

No specification governs this file; it is FerroSMART's own design.

## Specifications

The ground for each pin is the pin table in `docs/architecture.md` §2, which
records why the value is what it is.

| Item | Pin | Repeated in |
|---|---|---|
| SMART App Launch | 2.2.0 (STU 2.2, on FHIR R4 4.0.1) | `docs/architecture.md` §2, `docs/specs/smart-app-launch/PROVENANCE.md` |
| OAuth 2.0 and JOSE | the twelve RFCs of the table below | `docs/architecture.md` §2, `docs/specs/rfc/PROVENANCE.md` |
| OpenID Connect Discovery 1.0 | incorporating errata set 2 (2023-12-15) | `docs/architecture.md` §2, `docs/specs/openid-connect-discovery/PROVENANCE.md` |

## Corpora and machine-readable inputs

A corpus is pinned by commit, immutable publication or checksum, never by a
moving tag or a `latest` URL, and vendored by a committed `scripts/vendor/*.sh`
with a `PROVENANCE.md`. Each script reads its pin from this table, and
`scripts/checks/versions.sh` reads each vendored `PROVENANCE.md` back and
hashes the vendored bytes again, failing when either disagrees with its row.

| Item | Pin | Repeated in |
|---|---|---|
| SMART App Launch package | 2.2.0 registry sha1 `2e5b7caacf87523082507f6af2efdf25c24ad3d8` (`hl7.fhir.uv.smart-app-launch` from packages.fhir.org, FHIR 4.0.1, CC-BY-4.0) | `scripts/vendor/smart-app-launch.sh`, `docs/specs/smart-app-launch/PROVENANCE.md` |
| SMART App Launch source | `HL7/smart-app-launch` tag `2.2.0` commit `13449f93ba52d401d29ca9e72e8a4cbced8d6424` (the page sources the STU 2.2 publication renders) | `scripts/vendor/smart-app-launch.sh`, `docs/specs/smart-app-launch/PROVENANCE.md` |
| OpenID Connect Discovery 1.0 document | `openid-connect-discovery-1_0-errata2.html` sha256 `0401a07b35de50e914e195aa2c3c64cc4f6542464381c885d24a2623fbf75ec2` (the edition `openid-connect-discovery-1_0.html` serves) | `scripts/vendor/openid-connect-discovery.sh`, `docs/specs/openid-connect-discovery/PROVENANCE.md` |

### The RFCs

Each row pins the RFC Editor's text form (`https://www.rfc-editor.org/rfc/rfcNNNN.txt`)
by its sha256; an RFC is immutable once published, so the checksum is the
pin. `scripts/vendor/rfcs.sh` reads every `RFC` row here, refuses an RFC the
RFC Editor reports obsoleted, and records what updates it.

| Item | Pin | Repeated in |
|---|---|---|
| RFC 6749 | The OAuth 2.0 Authorization Framework, sha256 `f204fc8661d6c92d2ec6e0b54808f961a9ad26e792f57f312d9528335519bd71` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 6750 | The OAuth 2.0 Authorization Framework: Bearer Token Usage, sha256 `9dc385cf4ecdd85024e5a95e447ede9230e11700bf35251906b25b37557d604b` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7515 | JSON Web Signature (JWS), sha256 `ecbf84674118e62526511c1237e1deaa86aada86d25b247623a2a7e04ae62e40` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7517 | JSON Web Key (JWK), sha256 `681c19b92a85068716b7e89c5815aa821bd3f11c755ff1c641b40ae9851bb33c` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7519 | JSON Web Token (JWT), sha256 `fecd930e9ccf2276b95c0017c6c4ff5d09352e4bc3c7629946447894e0f97248` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7523 | JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants, sha256 `ae24f77a8fc4338903c805c6ace38def1f23d40194aea87b123b13c5b3d2d915` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7617 | The 'Basic' HTTP Authentication Scheme, sha256 `bc941321da9912fbb1bc92ad1820848ddfd3283dbfbc30f26ea2800bdaf541db` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7662 | OAuth 2.0 Token Introspection, sha256 `2b7d688cb849f093e860557ac97e6cddac2556d69a4386561b22cdf97bf13657` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8414 | OAuth 2.0 Authorization Server Metadata, sha256 `16c816e4e0fdbffb7e910ff3017867bf39debe9cb7f52f5cbc508a052ed660e8` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8725 | JSON Web Token Best Current Practices, sha256 `737b7013a2495dcfd5481cf4c57c87e2455d537c4cec1140c9096a71fcef0812` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9068 | JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens, sha256 `68d3ff3910c0f2340fd7b93b430e00053da845b6eebe095ebef0c8bfda5e14c5` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9700 | Best Current Practice for OAuth 2.0 Security, sha256 `9919d061d40a97886ca866b51c69389b6c81c65cd4b979056c14fdbebfcf622a` | `docs/specs/rfc/PROVENANCE.md` |

## Licence

| Item | Pin | Repeated in |
|---|---|---|
| Project licence | BUSL-1.1 | `LICENSE`, `NOTICE`, the SPDX header of every first-party file, the `license` field of the `ferrohealth-smart` manifest once the workspace lands |

`LICENSE` names Apache License 2.0 as a licence of its own, as the Change
License four years after each version. `ferrohealth-smart` is hand-written code
that implements the specifications above, so it is under BUSL-1.1 like the
rest of the family's own code; only generator-emitted code is published under
Apache-2.0 elsewhere in the family (`docs/architecture.md` §9).
`scripts/checks/versions.sh` fails on an Apache-2.0 or MIT claim in a
first-party file.

Vendored material keeps its upstream terms, recorded beside each vendored tree
in its `PROVENANCE.md`: CC BY 4.0 for the SMART App Launch package and page
sources, the IETF Trust Legal Provisions for the RFCs, and the OpenID
Foundation's notice for the Discovery specification.

The crate and tool pins (the Rust toolchain, the edition, the MSRV, the
third-party crates and the CI analyzers) join this file with the Cargo
workspace.
