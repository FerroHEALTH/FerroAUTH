<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->
<div align="center">

<img src="assets/brand/ferroauth-lockup-auto.svg" alt="FerroAUTH" width="290">

**Sign-in and access control for the FerroHEALTH products, as Rust libraries.**

[Documentation](https://docs.rs/ferrohealth-smart) ·
[Quick start](#quick-start) ·
[What ships today](#what-ships-today) ·
[Licensing](https://ferrohealth.eu/docs/licensing.html)

**Project**<br>
[![Release](https://img.shields.io/github/v/release/FerroHEALTH/FerroAUTH?sort=semver&logo=github&label=release)](https://github.com/FerroHEALTH/FerroAUTH/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/FerroHEALTH/FerroAUTH/ci.yml?branch=main&logo=githubactions&logoColor=white&label=CI)](https://github.com/FerroHEALTH/FerroAUTH/actions/workflows/ci.yml)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue)](LICENSE)
[![Docs](https://img.shields.io/docsrs/ferrohealth-smart?logo=docsdotrs&label=docs.rs)](https://docs.rs/ferrohealth-smart)

**Quality and security**<br>
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/FerroHEALTH/FerroAUTH/badge)](https://scorecard.dev/viewer/?uri=github.com/FerroHEALTH/FerroAUTH)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/FerroHEALTH/FerroAUTH/codeql.yml?branch=main&logo=github&label=CodeQL)](https://github.com/FerroHEALTH/FerroAUTH/actions/workflows/codeql.yml)
[![Signed releases](https://img.shields.io/badge/releases-signed-brightgreen?logo=github)](docs/release.md)
[![SLSA Build L3](https://slsa.dev/images/gh-badge-level3.svg)](docs/release.md)

</div>

## What FerroAUTH does

Every health application has to answer two questions on every request: who
is asking, and may they do this? Getting either wrong exposes patient data.
FerroAUTH answers both once, for every FerroHEALTH product, so each server
checks sign-in and permissions the same tested way.

It does not run a login page or issue passwords. A hospital keeps the
sign-in system it already has (such as Keycloak or Microsoft Entra ID), and
FerroAUTH checks the access tokens that system hands out: is the token
genuine, still valid, meant for this server, and does it grant this action
on this patient's record? It speaks SMART, the standard health apps use to
ask for access to openEHR and FHIR data.

### Who it is for

- **Hospital IT and security teams**, who can connect every FerroHEALTH
  product to their own identity provider and see one audit line per
  request.
- **Developers of health software in Rust**, who need SMART access checks
  and machine-to-machine sign-in without writing them again.

### Why you can trust what it claims

Every release is signed and carries SLSA build provenance, so you can check
that the crate you use is the one built here. The source is public, and
every function is in this repository: there is no paid edition with extra
features. The OAuth 2.0, SMART and OpenID Connect specifications the crates
implement are vendored in the repository at the versions
[`docs/VERSIONS.md`](docs/VERSIONS.md) pins, so you can check each check
against its standard.

## Part of FerroHEALTH

FerroHEALTH is five servers, each its own product, that reach each other
only over published standards: FerroEHR stores the record, FerroBRIDGE
translates it to FHIR and the OMOP research model, FerroFED connects records
across organisations and borders, FerroPIX matches patient identities, and
FerroTERM serves the code systems (the shared lists of medical terms). Work
that every server needs lives in three shared libraries: FerroAUTH for
sign-in and access control, FerroAUDIT for the audit trail, and FerroUI for
the web consoles. Every FerroHEALTH server checks its callers with
FerroAUTH.

## Quick start

Add the crate to a Rust project, with the web framework layer and the
openEHR scopes:

```sh
cargo add ferrohealth-smart@=0.6.0 --features axum,openehr
```

Pin the version exactly. The
[crate documentation](https://docs.rs/ferrohealth-smart) is the
integration guide, and
[`docs/architecture.md`](docs/architecture.md) has the configuration model.

## What ships today

- [Token checks](crates/ferrohealth-smart/README.md#what-it-does): the authorization server's keys read and rotated, every access token validated, and opaque tokens checked by introspection
- [SMART on openEHR scopes](crates/ferrohealth-smart/README.md#what-it-does) for templates, compositions and AQL queries, with the patient's EHR from the launch context
- [SMART on FHIR scopes](crates/ferrohealth-smart/README.md#what-it-does) with the patient compartment, beside the openEHR scopes in one token
- [Roles and assurance levels](crates/ferrohealth-smart/README.md#what-it-does) read from the token, for a product's route table
- [Machine sign-in](crates/ferrohealth-smart/README.md#what-it-does): HTTP Basic against Argon2id hashes, and the OAuth 2.0 client credentials grant
- [One audit line per request](crates/ferrohealth-smart/README.md#what-it-does), never with the token or any content
- [The SMART discovery document](crates/ferrohealth-smart/README.md#what-it-does) a product publishes for its clients
- [The policy decision](crates/ferrohealth-authz/README.md), `ferrohealth-authz`: attribute-based access with an embedded Cedar engine or a remote decision point

<details>
<summary><b>Published crates</b> (2)</summary>

| Crate | What it does | Version | Docs | Downloads |
|---|---|---|---|---|
| [`ferrohealth-smart`](https://crates.io/crates/ferrohealth-smart) | SMART App Launch and OAuth 2.0 resource server: token checks, SMART on openEHR and FHIR scopes, machine sign-in and the audit line | [![crates.io](https://img.shields.io/crates/v/ferrohealth-smart?logo=rust&label=crates.io)](https://crates.io/crates/ferrohealth-smart) | [![docs.rs](https://img.shields.io/docsrs/ferrohealth-smart?logo=docsdotrs&label=docs.rs)](https://docs.rs/ferrohealth-smart) | [![downloads](https://img.shields.io/crates/d/ferrohealth-smart?logo=rust&label=downloads)](https://crates.io/crates/ferrohealth-smart) |
| [`ferrohealth-authz`](https://crates.io/crates/ferrohealth-authz) | The policy decision: attribute-based access over the authenticated caller, with an embedded Cedar engine or a remote decision point | [![crates.io](https://img.shields.io/crates/v/ferrohealth-authz?logo=rust&label=crates.io)](https://crates.io/crates/ferrohealth-authz) | [![docs.rs](https://img.shields.io/docsrs/ferrohealth-authz?logo=docsdotrs&label=docs.rs)](https://docs.rs/ferrohealth-authz) | [![downloads](https://img.shields.io/crates/d/ferrohealth-authz?logo=rust&label=downloads)](https://crates.io/crates/ferrohealth-authz) |

</details>

## Learn more

- [`ferrohealth-smart` on docs.rs](https://docs.rs/ferrohealth-smart) and the [FerroHEALTH book](https://ferrohealth.eu/docs/)
- [Architecture](docs/architecture.md) and the [pinned specifications](docs/VERSIONS.md)
- Changelogs of [`ferrohealth-smart`](crates/ferrohealth-smart/CHANGELOG.md) and [`ferrohealth-authz`](crates/ferrohealth-authz/CHANGELOG.md), and [milestones](https://github.com/FerroHEALTH/FerroAUTH/milestones)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md), [code of conduct](CODE_OF_CONDUCT.md), [support](SUPPORT.md), [governance](GOVERNANCE.md) and [maintainers](MAINTAINERS.md)

## Licence

Business Source License 1.1 ([LICENSE](LICENSE)), with Apache License 2.0 as
the Change License four years after each version; the
[licensing page](https://ferrohealth.eu/docs/licensing.html) says when you
need a commercial licence from Cadasto B.V.
