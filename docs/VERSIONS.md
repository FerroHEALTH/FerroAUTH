<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Pinned version matrix

This file is the single source of truth for every version pin in FerroAUTH.
When it and a file that repeats a pin disagree, that is drift. Fix the
disagreement; never let either side silently win. `scripts/checks/versions.sh`
reads every vendored `PROVENANCE.md` and every vendored file back against the
rows below.

No specification governs this file; it is FerroAUTH's own design.

## Specifications

The ground for each pin is the pin table in `docs/architecture.md` §2, which
records why the value is what it is.

| Item | Pin | Repeated in |
|---|---|---|
| SMART App Launch | 2.2.0 (STU 2.2, on FHIR R4 4.0.1) | `docs/architecture.md` §2, `docs/specs/smart-app-launch/PROVENANCE.md` |
| IETF RFCs | the RFCs of the table below | `docs/architecture.md` §2, `docs/specs/rfc/PROVENANCE.md` |
| OpenID Connect Discovery 1.0 | incorporating errata set 2 (2023-12-15) | `docs/architecture.md` §2, `docs/specs/openid-connect-discovery/PROVENANCE.md` |
| OpenID Connect Core 1.0 | incorporating errata set 2 (2023-12-15) | `docs/architecture.md` §2, `docs/specs/openid-connect-core/PROVENANCE.md` |
| OpenID Connect RP-Initiated Logout 1.0 | final (2022-09-12) | `docs/architecture.md` §2, `docs/specs/openid-connect-rpinitiated/PROVENANCE.md` |
| SMART on openEHR | DEVELOPMENT (the ITS-REST draft at its amendment record 1.1.0, 2025-05-20, pinned by commit below; never a release) | `docs/architecture.md` §2 and §3.9, `docs/specs/smart-on-openehr/PROVENANCE.md` |

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
| SMART on openEHR source | `openEHR/specifications-ITS-REST` commit `9d25ea783f790512e05f908ef743626b4f7e8d2c` (the default branch head on 2026-10-16) path `docs/smart_app_launch` last change `5183c1f9274ed84096b29ea2b3977bc2e2b26247` (status DEVELOPMENT; `scripts/vendor/smart-on-openehr.sh --upstream` fails when the default branch has a newer commit touching the path) | `scripts/vendor/smart-on-openehr.sh`, `docs/specs/smart-on-openehr/PROVENANCE.md`, the `smart-on-openehr-upstream` job of `.github/workflows/specs.yml` |
| OpenID Connect Discovery 1.0 document | `openid-connect-discovery-1_0-errata2.html` sha256 `0401a07b35de50e914e195aa2c3c64cc4f6542464381c885d24a2623fbf75ec2` (the edition `openid-connect-discovery-1_0.html` serves) | `scripts/vendor/openid-connect-discovery.sh`, `docs/specs/openid-connect-discovery/PROVENANCE.md` |
| OpenID Connect Core 1.0 document | `openid-connect-core-1_0-errata2.html` sha256 `4d016752a645e8a3c259baa4173b5a90cb6c82898ce868fc8444adde262a5aed` (the edition `openid-connect-core-1_0.html` serves) | `scripts/vendor/openid-connect-core.sh`, `docs/specs/openid-connect-core/PROVENANCE.md` |
| OpenID Connect RP-Initiated Logout 1.0 document | `openid-connect-rpinitiated-1_0-final.html` sha256 `246432dafaa5556d896fa9b9ae4284b213ff6921b33478ed3b46bd6bd4aab804` (the edition `openid-connect-rpinitiated-1_0.html` serves) | `scripts/vendor/openid-connect-rpinitiated.sh`, `docs/specs/openid-connect-rpinitiated/PROVENANCE.md` |
| NIST SP 800-162 document | `NIST.SP.800-162.pdf` sha256 `ea90ee967a7011c8de5cfaffe0820d157167edefdea5fc2a84af730af4295cd7` (January 2014, with the updates of 2019-08-02) | `scripts/vendor/nist-sp-800-162.sh`, `docs/specs/nist-sp-800-162/PROVENANCE.md` |
| Cedar language documentation | `cedar-policy/cedar-docs` commit `5d8a02fda9ddf629b9989b0e0e2fb16215d394e4` (the default branch head on 2026-10-25) paths `docs/collections/_policies`, `_auth` and `_schema` | `scripts/vendor/cedar-docs.sh`, `docs/specs/cedar-docs/PROVENANCE.md` |
| IHE IUA supplement | `IHE/ITI.IUA` tag `2.5` commit `a8e20c92928b7560ee07a410922187757248c8b9`, the Revision 2.5 Trial Implementation supplement text (ITI-71, ITI-72, ITI-102, ITI-103) and its figures, the edition FerroHEALTH/FerroFED vendors (CC-BY-4.0) | `scripts/vendor/ihe-iua.sh`, `docs/specs/ihe-iua/PROVENANCE.md` |
| Nuts RFC021 | `nuts-foundation/nuts-specification` commit `7c0de533b8cce537812b6647542e5719c93433a8`, RFC021 (VP Token Grant Type), the commit FerroHEALTH/FerroFED vendors (CC-BY-SA-4.0, per the document's Copyright Notice) | `scripts/vendor/nuts-rfc.sh`, `docs/specs/nuts-rfc/PROVENANCE.md` |
| Microsoft Entra documentation | `MicrosoftDocs/entra-docs` commit `219d8d57b01779e72e6d5449dc9341334c1fb906` (the default branch head on 2026-11-05), the access token claims reference, the optional claims reference and the on-behalf-of flow (CC-BY-4.0 per the README, MIT per the LICENSE file) | `scripts/vendor/entra-docs.sh`, `docs/specs/entra-docs/PROVENANCE.md` |
| SCIM workload identity federation guide | `AzureAD/SCIMReferenceCode` commit `21b92c8f28383e30f8c304908b126682af2370d7` (the default branch head on 2026-11-05), `Workload-Identity-Federation-for-SCIM-Provisioning.md` and its figures (MIT) | `scripts/vendor/scim-workload-identity.sh`, `docs/specs/scim-workload-identity/PROVENANCE.md` |
| Keycloak documentation | `keycloak/keycloak` tag `26.8.2` commit `e514445f9dcdabc5bdcf67cab56c1e49655de067`, the token exchange chapter, the server administration guide's service account, protocol mapper, audience, user profile and identity brokering sections, the server guide's container chapter, the audience mapper's two source files and the default user profile (Apache-2.0) | `scripts/vendor/keycloak-docs.sh`, `docs/specs/keycloak-docs/PROVENANCE.md` |
| Okta OpenID Connect and OAuth 2.0 API | pin-set digest `5eabc84f3fc280ea72504609b93738068dce65c672d8fafb2a2f758ef3e16706` over the one page the script pins by URL and sha256; cache only, never committed ("All rights reserved") | `scripts/vendor/okta.sh`, `docs/specs/okta/PROVENANCE.md` |
| Microsoft Graph documentation | pin-set digest `e57d83b8670cc8285f92127af8f5717c49268af10083dadb1ce138fd7278b91c` over five files of `microsoftgraph/microsoft-graph-docs-contrib` commit `bb35043c742d4406d73ccae904c05fbfca7c7428` (the default branch head on 2026-11-05), pinned by URL and sha256: `directoryObject: getMemberObjects`, `directoryObject: getMemberGroups`, the throttling guidance and the two licence files; cache only, never committed (`LICENSE.md` states CC BY-NC-ND 3.0 US, `LICENSE` holds CC BY 4.0) | `scripts/vendor/microsoft-graph.sh`, `docs/specs/microsoft-graph/PROVENANCE.md` |
| eHDSI specifications | pin-set digest `c08730ff34b06631cea5422a1fca8a98752acccbf2cb05817f08b5cbae8a2cae`: the SAML Profile 10.0.0, Section II Security Services 10.0.0, the Service Location and Capability Lookup Profile 10.0.0, the NCPeH Components Specifications 10.0.0 and the Interoperability Specifications 8.0.1, supplied by the owner from the eHDSI wiki (EU Login) and committed (each cover: PU, reuse authorised with the source acknowledged), the files and sha256 values FerroHEALTH/FerroFED vendors; the MyHealth@EU Requirements Catalogue 10.0.0 read and not committed (no reuse statement) | `scripts/vendor/ehdsi-specifications.sh`, `docs/specs/ehdsi-specifications/PROVENANCE.md` |
| EU legal acts | pin-set digest `c4c72048aa7e1f1c69321f23afa9ba41c8149252f8ff0277ea143e6c34a92123`: Implementing Regulation (EU) 2026/2099, Regulation (EU) 2016/679 (the GDPR) and Commission Decision 2011/833/EU, the English Official Journal XHTML at its Cellar manifestation, reused under that Decision | `scripts/vendor/eu-law.sh`, `docs/specs/eu-law/PROVENANCE.md` |
| Federation Tier with AQL specification | `syntaric/openehr-federation-spec` commit `b4242c291b08990df718bbfaa1188e4865478e5a`, untagged (declares 1.0.1), the commit FerroHEALTH/FerroFED vendors; Annex B (the Dutch Generic Functions), `antora.yml` and `LICENSE` (CC0-1.0) | `scripts/vendor/federation-spec.sh`, `docs/specs/federation-spec/PROVENANCE.md` |

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
| RFC 8707 | Resource Indicators for OAuth 2.0, sha256 `3b89844a938b9219571931b664ed4a7b380555a4dda1df4e9445a2f72188e76b` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7638 | JSON Web Key (JWK) Thumbprint, sha256 `98b29ab9652070e6a5fec748d43e221bbedc66b6b22e05903fb5366c04ef3110` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9449 | OAuth 2.0 Demonstrating Proof of Possession (DPoP), for reference, sha256 `3842c58e1f6043389416023b9bb8d765048266024982fbbd90640e05943f4e13` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8705 | OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens, sha256 `6e45a1ee94c6a6a177a4cb077fe67d74bd70c1218c9362f2db2f153239612414` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9470 | OAuth 2.0 Step Up Authentication Challenge Protocol, sha256 `02d742f49cc0a03fb09197563c436b6f38928a71b0d8e41cde9cfe0362363e56` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8259 | The JavaScript Object Notation (JSON) Data Interchange Format, sha256 `61a5378f4255c720beb2a4b4a63b29540147c140f36988bf086291989b4cd2d7` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 6454 | The Web Origin Concept, sha256 `6a42d01bf407e87255e3bd8d870fda0f473e09f3272592ba438b57c983bc5399` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7643 | System for Cross-domain Identity Management: Core Schema, sha256 `df799c112a3fa5be3c0fe054c08b1f4eb5d07590c4c8343a014c4537bf638ae3` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 9396 | OAuth 2.0 Rich Authorization Requests, sha256 `d6a8f032d8a585daae1c33a8c7b6e539d199f886ec8cc1c7898436f7f2eed29c` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7636 | Proof Key for Code Exchange by OAuth Public Clients, sha256 `1972e5d81cbaba7066cfd46374207bc2b4546b085ed5dd9b034e79e023e0ca31` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7009 | OAuth 2.0 Token Revocation, sha256 `b2f346d5a87ba9d7f09047901257a65f7ac0b26352095969c25821afab447829` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7521 | Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants, sha256 `d5d97b3e691c9bbc495c277cc2cd79316b82486991468fc346a96ab59ba4b3c8` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 7522 | Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants, sha256 `87656a015c74b2cce4ed74fdf785ea2cf824e8d13cc53860d40fac3e57569afd` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 8693 | OAuth 2.0 Token Exchange, sha256 `358d658014738bf4dc56c8aae2094ce716ede23b6d5a80488a7dc8e8d72da609` | `docs/specs/rfc/PROVENANCE.md` |
| RFC 3986 | Uniform Resource Identifier (URI): Generic Syntax, sha256 `3102dae4b68cebe40337730312fcb612297b8928547267e8b3d1ee6002b2d683` | `docs/specs/rfc/PROVENANCE.md` |

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
sources, the IETF Trust Legal Provisions for the RFCs, Apache License 2.0
for the SMART on openEHR source and the Cedar language documentation, the
OpenID Foundation's notice for the three OpenID Connect specifications, the
public domain of a United States Government work for NIST SP 800-162, CC BY
4.0 for the IHE IUA supplement, CC BY-SA 4.0 for Nuts RFC021, the README's
CC BY 4.0 grant and the LICENSE file's MIT text for the Microsoft Entra
documents, MIT for the SCIM workload identity federation guide and Apache
License 2.0 for the Keycloak documentation. The Okta API reference states
"All rights reserved" and grants no licence, so `scripts/vendor/okta.sh`
fetches it into the git-ignored `.vendor-cache/okta/` and only its
`PROVENANCE.md` is committed. The Microsoft Graph reference pages carry
two licence statements that disagree, CC BY-NC-ND 3.0 United States in
`LICENSE.md` and the CC BY 4.0 text in `LICENSE`, so
`scripts/vendor/microsoft-graph.sh` keeps them in
`.vendor-cache/microsoft-graph/` the same way. The eHDSI documents are reused as each cover
allows ("Reuse is authorised, provided the source is acknowledged"), with
the source line of the cover as the acknowledgement; the MyHealth@EU
Requirements Catalogue states no reuse terms, so only its sha256 and
version are recorded and no copy is committed or cached. The EU legal acts
are reused under Commission Decision 2011/833/EU, vendored beside them, and
the Federation Tier Annex B is under CC0 1.0.

## The toolchain and the crate

| Item | Pin | Repeated in |
|---|---|---|
| Rust toolchain | 1.99.1, profile `minimal`, components `rustfmt` and `clippy` | `rust-toolchain.toml` |
| Rust edition | 2024 | `Cargo.toml` `[workspace.package] edition`, `rustfmt.toml` |
| MSRV | 1.98 | `Cargo.toml` `[workspace.package] rust-version` |
| `ferrohealth-smart` | the workspace version (read it in the manifest; a release moves it), with the release tag `ferrohealth-smart-vX.Y.Z` and the section of its own `CHANGELOG.md` | `Cargo.toml` `[workspace.package] version`, `Cargo.lock`, `crates/ferrohealth-smart/CHANGELOG.md` (held together by `scripts/checks/crate-version-guard.sh`) |
| `ferrohealth-authz` | its own version line (read it in the manifest; a release moves it), with the release tag `ferrohealth-authz-vX.Y.Z` and the section of its own `CHANGELOG.md` | `crates/ferrohealth-authz/Cargo.toml` `[package] version`, `Cargo.lock`, `crates/ferrohealth-authz/CHANGELOG.md` (held together by `scripts/checks/crate-version-guard.sh`) |
| `ferrohealth-session` | its own version line (read it in the manifest; a release moves it), with the release tag `ferrohealth-session-vX.Y.Z` and the section of its own `CHANGELOG.md` | `crates/ferrohealth-session/Cargo.toml` `[package] version`, `Cargo.lock`, `crates/ferrohealth-session/CHANGELOG.md` (held together by `scripts/checks/crate-version-guard.sh`) |
| Third-party crates | the `[workspace.dependencies]` table, each version checked against crates.io on 2026-10-19 | `Cargo.toml`, `Cargo.lock` |

## The CI tools

| Item | Pin | Repeated in |
|---|---|---|
| zizmor | 1.31.1 | `.github/workflows/ci.yml` |
| actionlint | 1.7.12, image digest `sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667` | `.github/workflows/ci.yml` |
| shellcheck | 0.11.0 | `.github/workflows/ci.yml` |
| cargo-semver-checks | 0.51.0, installed through `taiki-e/install-action`, which verifies the archive against its manifest checksum | read from this row by `scripts/checks/semver.sh --pin` for `.github/workflows/ci.yml` and `.github/workflows/release.yml` |
| cargo-nextest, cargo-deny | the newest release `taiki-e/install-action` resolves at run time | `.github/workflows/ci.yml` |
| Keycloak test image | `quay.io/keycloak/keycloak:26.8.2`, index digest `sha256:3879c623248408de29a5303178b5816c77e8dfef3890c361f8c0bbeaa979ba3b`, the release the Keycloak documentation pin names, run only by the live case behind `FERROHEALTH_KEYCLOAK_E2E=1`, which CI's `keycloak-live` job sets | `crates/ferrohealth-smart/tests/it/keycloak_live.rs` |
| GitHub Actions | every `uses:` pinned to a full commit SHA with its version in a trailing comment, bumped by Dependabot | `.github/workflows/*.yml`, `.github/actions/setup-rust/action.yml` |
