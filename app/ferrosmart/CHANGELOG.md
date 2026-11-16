<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog

All notable changes to FerroSMART are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `[ferrosmart.upstream.private_key_jwt]`: FerroSMART authenticates at its
  upstream provider with a JWT its current `[ferrosmart.keys]` key signs
  (OpenID Connect Core 1.0 §9), at the `algorithm` the provider's
  registration names (an RSA one, RS256 by default), naming the key's
  certificate by `x5t#S256` when `certificate_file` is set. A client secret
  beside it, an algorithm the key cannot sign and a certificate of another
  key are refused at load. The Entra ID example uses it with a certificate
  credential and `PS256`, and its contract test verifies the assertion the
  stub receives (#569).

### Changed

- The Keycloak example authenticates FerroSMART with `private_key_jwt`: the
  realm's client takes the `client-jwt` authenticator and reads
  FerroSMART's `{issuer}/jwks`, so `compose.keycloak.yaml` and the CI lane
  no longer make a `keycloak_client_secret` (#569).
- Microsoft Entra ID and Okta as the upstream login, each with an example
  configuration under `examples/` and no provider code. Entra ID: a
  single-tenant app registration's v2.0 authority, the app roles in `roles`
  and the directory extension attribute `fhirUser` as the optional claim
  `extn.fhirUser`; the multitenant `/common` and `/organizations`
  authorities fail discovery, since their metadata names another issuer.
  Okta: the `default` custom authorization server, a `groups` claim and a
  custom `fhir_user` claim. Contract tests run each example through a
  standalone launch against a stub serving the provider's published
  discovery document, key set and token answer (#524, #525).
- `compose.keycloak.yaml`, an override of the quickstart that runs Keycloak
  with the example realm as the login of `compose.yaml`'s FerroSMART, in the
  same compose project (#522).
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
  `need_patient_banner`, `tenant`, and `ehrId` for an openEHR server) is
  checked against SMART's rules, and an unknown parameter or claim is
  refused. At `/authorize` a `launch` with the `launch` scope is redeemed
  for that app and `aud`, the consent page offers `launch`, its
  `launch/patient` and `launch/encounter` hints and the `patient/` scopes
  its patient allows, and the token response carries the context when the
  person keeps `launch`, with `patient`, `encounter` and `ehrId` in the
  access token too. The SMART configuration lists `launch-ehr`,
  `context-ehr-patient`, `context-ehr-encounter`, `context-banner` and
  `permission-patient`.
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
- The refresh token grant at the token endpoint (SMART App Launch 2.2.0,
  Refresh access token): a public client by `client_id`, a confidential
  one by its assertion, each only with its own token. Every refresh
  rotates the token; a rotated token presented again revokes its grant
  with every token under it (RFC 9700 §4.14.2). A `scope` may narrow the
  grant and never widen it, the rotated token keeps the grant's scope, and
  the answer carries the launch context. `[ferrosmart] refresh_idle`
  (thirty days) and `online_idle` (eight hours) set how long an
  `offline_access` and an `online_access` refresh token last unused, and
  an `online_access` one ends with its upstream session. A client
  registers `refresh_token` only beside `authorization_code`. The code
  exchange opens the grant and answers its first refresh token when the
  person granted `offline_access` or `online_access`, which the consent page
  offers only to a client whose ceiling lists it and that registers
  `refresh_token`; each login at the upstream provider is recorded as the
  session an `online_access` grant ends with, and withdrawing a remembered
  consent revokes its grants (#518).
- `POST /backchannel-logout`, the back-channel logout URI to register at
  the upstream provider (OpenID Connect Back-Channel Logout 1.0): a Logout
  Token that checks ends the upstream sessions it names and revokes their
  `online_access` grants with every token under them, leaving
  `offline_access` grants; a token that does not check answers `400` with an
  OAuth 2.0 error body, every answer `no-store` (#518).
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
- The audit records, kept in FerroSMART's own store (migration 0007): every
  token request, issued or refused, is the ITI-71 audit event in the form
  of BALP 1.1.4's `IHE.IUA.71`, and every login at the upstream provider a
  DICOM User Authentication event of type Login, each a FHIR R4
  `AuditEvent` written through `ihe-atna`. An issued token and its record
  commit in one transaction; a token request whose record cannot be
  committed is answered `503` with no token, and a login whose record
  cannot be committed goes no further. A record names the client, the
  person's pairwise subject and the token's `jti`, never a token, an
  assertion, a verifier or a secret. The optional `[ferrosmart.audit.feed]`
  forwards the records to an Audit Record Repository over the ITI-20 ATX:
  FHIR Feed, and `GET /audit` reads them by subject and time with a token
  carrying `system/AuditEvent.rs` (#534).
- The Inferno SMART App Launch test kit lane: the kit's STU 2.2 suite runs
  in CI against FerroSMART with FerroEHR as the resource server, every
  exchange over TLS, and fails on any result that differs from the expected
  results, which hold each test to `pass` outside a listed exception. Group
  3, Backend Services, runs; the groups whose steps have not landed are
  listed as pending in every run (#520).
- Every other write FerroSMART makes for a person or a client commits with
  its audit record in one transaction: a code issued, a consent remembered
  or withdrawn, a token or a grant revoked, a refresh token rotated or
  reused, a code reused, and an upstream session ended (DICOM Logout). Their
  codes are in `urn:ferrosmart:audit-event`, our own design where no IHE or
  BALP pattern exists, and a write whose record cannot be committed does
  not happen (#554).

### Fixed

- The token endpoint answers a request from one of the client's registered
  origins, the origins of its redirect URIs, with
  `Access-Control-Allow-Origin` and `Vary: Origin`, so a browser app can
  read its token response (SMART App Launch 2.2.0, Considerations for CORS
  support). Every other origin gets no CORS header (#560).
