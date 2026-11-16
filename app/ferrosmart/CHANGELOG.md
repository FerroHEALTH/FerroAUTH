<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog

All notable changes to FerroSMART are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A Keycloak example as the upstream login: a realm with fixed ids whose
  confidential client `ferrosmart` takes the authorization code flow with
  PKCE S256, and whose mappers write the user's `fhir_user` attribute and
  realm roles into the ID Token, and the `[ferrosmart.upstream]` and
  `[[ferrosmart.role]]` configuration that reads them, with no Keycloak code.
  CI drives a SMART standalone launch through it to a token with the mapped
  `fhirUser` (#522).
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
- The authorization code flow of SMART App Launch 2.2.0, standalone
  launch: the authorization endpoint by `GET` and `POST` (code with PKCE
  `S256` only, `aud` among the configured resource servers, the redirect URI
  matched exactly, an untrusted client or redirect shown and never
  redirected to), the login at any OpenID Connect provider through
  `[ferrosmart.upstream]`, the person's pairwise `sub`, `fhirUser` and roles
  from configured claims, the scopes narrowed by the client's ceiling and
  `[[ferrosmart.role]]` before the consent page, which FerroUI draws in the
  FerroSMART brand with no script and lets the person untick any scope,
  decline or remember the choice, the single-use code with `state` and
  `iss` (RFC 9207), and the code exchange for public and asymmetric clients
  with an RFC 9068 access token, an RS256 ID Token carrying `fhirUser` and
  the `smart_style_url` of `[ferrosmart.branding]`;
  a second use of a code revokes what the first issued. `GET /manage` lists
  the remembered choices and withdraws one, and the OpenID Connect
  discovery document and the App Launch SMART configuration describe the
  login once it is configured (#515).
- The introspection endpoint, `POST /introspect` (RFC 7662 with SMART App
  Launch 2.2.0, Token Introspection): a client whose ceiling lists
  `system/introspect` authenticates by its assertion or presents a bearer
  token FerroSMART issued for its own issuer with that scope, and may
  introspect any client's token. An active token answers `scope`,
  `client_id`, `exp`, `iat`, `sub`, `aud`, `iss`, the grant's launch
  context and `fhirUser`; an expired, revoked, forged or unknown token
  answers `{"active": false}` alone (#518).
- The revocation endpoint, `POST /revoke` (RFC 7009): a confidential client
  by its assertion, a public client by `client_id`, each only for its own
  tokens. Revoking a refresh token revokes its grant with every token under
  it; an unknown token answers `200` (#518).
- Migration 0005: the grants, the refresh tokens stored as their SHA-256,
  the upstream sessions an `online_access` grant ends with, and the grant
  of each access token, so revocation reaches every replica at once. The
  RFC 8414 metadata names both endpoints and their client authentication
  methods (#518).
- The release lane: a `ferrosmart-vX.Y.Z` tag builds `x86_64` and `aarch64`
  tarballs for GNU and musl libc, each with its checksum, a CycloneDX and an
  SPDX SBOM and SLSA Build Level 3 provenance signed through Sigstore, and
  the image `ghcr.io/ferrohealth/ferrosmart` for `linux/amd64` and
  `linux/arm64` on distroless static, pushed by digest with its provenance
  and SBOMs as OCI referrers. Every finding of a full scan of the image and
  the tarballs needs an OpenVEX judgement before the release publishes, and
  the image is tagged only once it carries no fixable HIGH or CRITICAL
  finding, and a weekly scan of the published image files an issue for a
  new fixable one. `compose.yaml` is the quickstart beside PostgreSQL,
  attached to every release (#519).
