<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog

All notable changes to FerroSMART are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The `ferrosmart` server: `serve`, `config check` and `healthcheck` on the
  family's stack, the `[ferrosmart]` configuration with its issuer and
  `RS256` signing key ring (current, previous and next key), the RFC 8414
  metadata, the SMART configuration and the JWK Set (#514).
- The PostgreSQL store with its embedded migrations, run under the
  advisory lock of `sqlx` at start, and its readiness indicator; the client
  registry of `[[ferrosmart.client]]` tables, each checked against SMART's
  registration rules (a JWK Set by URL or by value, with `kty`, `kid` and
  bare public members) and written to the store at every start (#514).
- The token endpoint with SMART Backend Services' client credentials grant.
  The `private_key_jwt` assertion is checked as SMART App Launch 2.2.0,
  Client Authentication: Asymmetric, has it: RS384 or ES384, `typ` `JWT` or
  `client-authentication+jwt`, one key by `kid` from the registered set or
  URL, a `jku` only as registered, an `aud` of one string naming the token
  endpoint or the issuer, an `exp` at most five minutes ahead, and a `jti`
  used once across replicas. The scope is narrowed to the client's ceiling,
  the audience is chosen by `resource` (RFC 8707) among
  `[[ferrosmart.resource]]`, and the RFC 9068 access token is signed under
  `RS256`, recorded in the store and answered with `no-store`. Each refusal
  is its RFC 6749 §5.2 error, and every issue and refusal writes an audit
  line (#514).
- The EHR launch API, FerroSMART's own design since SMART defines none
  (#517). An EHR client whose ceiling lists `system/launch.c` posts the
  launch context to `POST /launch`, authenticated with its
  `private_key_jwt` assertion as at the token endpoint, and receives a
  single-use `launch` value that lives five minutes, stored as its SHA-256
  and bound to the EHR, the app (`app_client_id`) and the resource server
  (`resource`). An EHR can instead sign a `launch+jwt` with a key of its
  registered JWK Set and hand it to the app as the `launch` value; its
  `iss`, sole `aud`, `exp` and `jti` are checked and a replay is refused.
  The context (`patient`, `encounter`, `fhirContext`, `intent`,
  `need_patient_banner`, `smart_style_url`, `tenant`, and `ehrId` for an
  openEHR server) is checked against SMART's rules, and an unknown
  parameter or claim is refused.
