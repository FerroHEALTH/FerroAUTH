<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog
<!-- ANCHOR: book -->

All notable changes to FerroSMART are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A `[[ferrosmart.client]]` may register its app's `launch_uri`, and the
  EHR launch API takes `app_launch_uri` in place of `app_client_id`, so an
  EHR acting on a SMART `task-ehr-launch` Task, which names the app only by
  its launch URL, can register the launch. The URLs are compared after RFC
  3986 §6.2.2 normalization, and two clients may not register one (#659).
- The EHR launch API takes a Task's `appContext` (at most 8192 bytes), and
  the token response of that launch carries it unchanged as `appContext`
  (SMART App Launch 2.2.0, Task profile for requesting a SMART launch)
  (#660).
- An administrator can approve one of the organisation's own apps for its
  staff with `[ferrosmart.client.organisation_approval]` (scopes, who,
  when), so a professional who opens it sees no consent page (SMART App
  Launch 2.2.0, Obtain authorization code, Response). Only `user/` scopes
  with their launch, OpenID, refresh and extension scopes can be approved;
  a request with a `patient/` scope, a patient's own login and a request
  beyond the approval show the page. The granted scope never exceeds the
  person's roles. Each skipped page is audited with the approval as its
  basis, the management page lists the app as approved by the
  organisation, and clearing the approval revokes every token issued on it
  at the next start (#643).
- The access token of a user flow carries the person's roles in a `roles`
  claim (RFC 9068 §2.2.3.1): the roles the identity provider's
  `role_claims` carry that a `[[ferrosmart.role]]` names, fixed at login
  and kept through every refresh. The introspection response carries them
  too. A Backend Services token carries none (#649).
- A `[[ferrosmart.role]]` may grant extension scopes, those that start with
  two underscores (SMART App Launch 2.2.0, Scopes and Launch Context,
  Extensibility), such as FerroEHR's `__ferroehr.platform`. A person is
  granted one when the request asks for it, the client's ceiling lists it
  and one of their roles grants it; the consent page names it in plain
  words, and `scopes_supported` lists every extension scope a role grants.
  Any other scope outside the SMART set is still never granted to a person
  (#647).
- An openEHR `[[ferrosmart.resource]]` can name the platform's FHIR server
  as its `fhir_base`, with the `subject_system` of the `Patient.identifier`
  that names the EHR's subject. At such a base the patient picker searches
  the FHIR server and looks the chosen patient's EHR up at the openEHR
  server, each as the signed-in person, so a standalone launch with
  `launch/patient` gets both `patient` and `ehrId` (SMART on openEHR draft,
  Context Selection and Service Discovery). A patient without an EHR the
  person may see is told so and enters no context (#574).
- The introspection endpoint takes a confidential symmetric client's
  secret, by HTTP Basic or in the form, as the token endpoint does (RFC
  7662 §2.1, RFC 6749 §2.3.1), so a gateway that introspects with
  `client_secret_basic`, such as Apache APISIX, can sit in front of a
  resource server. The client's ceiling lists `system/introspect`; a wrong
  secret answers `401` `invalid_client` and a client without the scope
  `401` `unauthorized_client`, each challenged `Basic`. The metadata's
  `introspection_endpoint_auth_methods_supported` lists
  `client_secret_basic` and `client_secret_post` beside `private_key_jwt`
  (#639).

### Fixed

- The upstream login refuses an ID Token without `iat` (OpenID Connect
  Core 1.0 §2), and takes one without `kid` when a single key of the
  provider's set fits its algorithm. The OpenID Foundation conformance
  suite's relying party modules `oidcc-client-test-missing-iat` and
  `oidcc-client-test-kid-absent-single-jwks` found both (#646, #648).

## [0.1.0] - 2026-11-19

### Added

- The book shows every page a person meets during a launch, in the light
  and the dark theme: the consent page of a clinician app and of a patient
  app, the patient picker, the management page and the three error pages.
  The README and the landing page show the consent page (#623).
- `[ferrosmart.brand]` publishes the deployment's User Access Brands Bundle
  at `GET {issuer}/brands` (SMART App Launch 2.2.0, User Access Brands and
  Endpoints): a primary brand that references every FHIR endpoint, its
  portals and its affiliated brands, as `application/fhir+json` with CORS
  for any origin and a weak `ETag` an `If-None-Match` answers with `304`.
  `Bundle.timestamp` is the last change to the contents and each resource's
  `meta.lastUpdated` its own, which the store keeps across restarts and
  replicas. The Bundle is held to the guide's
  profiles with `ferrobridge-validator` over the package set
  `scripts/vendor/fhir-packages.sh` fetches (#602).
- The management page lists every app that holds a live `offline_access`
  or `online_access` grant of the person, remembered or not, says how long
  it stays connected, and withdraws it, as SMART App Launch 2.2.0, Best
  Practices asks a server to remind people which apps have offline access
  (#608).
- The consent and management pages put plain words before a FHIR resource
  type, "Measurements and test results (Observation)", for the common
  types (SMART App Launch 2.2.0, Best Practices, Considerations for Scope
  Consent) (#608).
- `ferrosmart client hash-secret` reads a confidential symmetric client's
  secret on standard input and prints its Argon2id hash at the OWASP floor
  (m=19456, t=2, p=1) with a fresh salt, the string `secret_hash_file`
  holds. The Inferno lane runs its EHR launch with a symmetric client made
  this way (#601).
- A standalone launch that asks for `launch/patient` and `launch/encounter`
  at a FHIR resource server gets an encounter step in the picker: the
  chosen patient's encounters, searched as the signed-in person with the
  scope `user/Encounter.rs`, latest first. The person picks one or goes on
  without, which drops `launch/encounter` from the offer. The chosen
  encounter is read again and enters the context only when its `subject` is
  that patient, and the token response and the access token carry it. The
  discovery document lists `context-standalone-encounter` when a resource
  server is a FHIR one (SMART App Launch 2.2.0, Scopes and Launch Context,
  Standalone apps) (#604).
- SMART v1 scopes (`patient/Observation.read`, `.write`, `.*`) are
  admitted by their v2 form against a client's ceiling and a person's roles
  and granted as asked, as SMART App Launch 2.2.0, Scopes and Launch
  Context has a server process them, and the discovery document lists
  `permission-v1` (#604).
- Confidential symmetric clients (SMART App Launch 2.2.0, Client
  Authentication: Symmetric): `kind = "confidential_symmetric"` with
  `secret_hash_file`, the Argon2id PHC hash of the client's secret at the
  OWASP floor, never the secret. The client authenticates at the token and
  revocation endpoints by `client_secret_basic` or `client_secret_post`
  (RFC 6749 §2.3.1); a failed Basic credential answers `401` with
  `WWW-Authenticate: Basic`, two methods in one request are refused, and
  the client credentials grant and a JWK Set are refused at load. The
  discovery documents list both methods and `client-confidential-symmetric`.
  Migration `0008` adds the hash to the client table (#601).
- The patient picker at an openEHR resource server: for a standalone launch
  with `launch/patient` at an openEHR base whose `[[ferrosmart.resource]]`
  table names a `subject_namespace`, the signed-in person enters the
  patient's identifier and FerroSMART looks the EHR up through ITS-REST
  (`GET [base]/ehr?subject_id=…&subject_namespace=…`) with a token of the
  person's own, living 30 seconds and revoked after use. The chosen EHR is
  looked up again before its `ehrId` enters the launch context, the token
  response and the access token, and every lookup writes the EHDS access
  record (#571).
- `[ferrosmart.upstream.private_key_jwt]`: FerroSMART authenticates at its
  upstream provider with a JWT (OpenID Connect Core 1.0 §9) signed by the
  current key of its own assertion ring,
  `[ferrosmart.upstream.private_key_jwt.keys]`, read as `[ferrosmart.keys]`
  is and published apart at `{issuer}/upstream-jwks`, so an assertion key
  never signs a token (RFC 8725 §3.12). It signs at the `algorithm` the
  provider's registration names (RS256 by default) and names the key's
  certificate by `x5t#S256` when `certificate_file` is set. A client secret
  beside it, an algorithm the key cannot sign, a certificate of another key
  and an assertion ring sharing a key with the token ring are refused at
  load. The Entra ID example uses it with a certificate
  credential and `PS256`, and its contract test verifies the assertion the
  stub receives (#569).
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
- ZITADEL as the upstream login (`compose.zitadel.yaml`, an override of the
  quickstart): `app/ferrosmart/examples/zitadel/bootstrap.sh` makes the
  project, its role, the application, the user and an Actions v2 target
  through ZITADEL's v2 APIs and writes FerroSMART's configuration, and the
  target, `tools/zitadel-fhir-user`, writes the user's `fhirUser` claim. CI
  drives a SMART standalone launch through it to a token with the mapped
  `fhirUser` and a role-granted scope (#523).
- `[ferrosmart.upstream] trusted_audiences`: the audiences an upstream ID
  Token may name beside FerroSMART's client id (OpenID Connect Core 1.0
  §3.1.3.7 item 3) (#523).
- The Inferno lane runs group 1, Standalone Launch: the person picks the
  lane's patient at the patient picker, which searches FerroBRIDGE's
  facade, so the launch carries `launch/patient`. All four groups of the
  kit's STU 2.2 suite run, and every test passes against FerroBRIDGE
  0.0.27, whose facade answers CORS for the kit's origin (#520).
- The Inferno lane runs its FHIR server on the family's own stack: FerroBRIDGE's
  facade, with FerroEHR as its CDR, serves the person's `fhirUser` as a
  Practitioner, and Keycloak is the upstream login. Group 4, Token
  Introspection, and group 2, EHR Launch, with the lane as the EHR, run beside
  group 3, and the discovery exception that waited on the authorization
  endpoint is gone (#520).
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
- The EHR launch API writes audit records (#558): a registration commits
  with its launch row and a redemption with its use in one audited
  transaction (`launch-registered`, `launch-redeemed`), and a refused
  registration or redemption is a `launch-refused` record. A launch whose
  record cannot be kept is not kept. No record holds the launch value or a
  context value.
- The patient picker of a standalone launch: a client that may ask for
  `launch/patient` at a FHIR resource server is shown, after the login and
  before the consent, a page that searches `Patient` by name or identifier
  as the signed-in person, with a token of FerroSMART's own carrying their
  pairwise `sub` and `fhirUser`, scope `user/Patient.rs`, living 30 seconds
  and revoked after the request. The chosen patient is read again as them,
  enters the launch context, and reaches the token response and the access
  token as an EHR launch's does. Every search and read writes the access
  record of Regulation (EU) 2025/327 Annex II 3.2 through `ehds-logging`,
  and a failed search is an error page (#516).

### Changed

- The consent, picker, management and error pages draw FerroSMART's own
  mark, the shield with the keyhole, through FerroUI 0.6.11
  (`view::shell::ferrosmart_mark`), in the brand's yellow fill roles, where
  they drew a key glyph; the error pages now lead with the same lockup
  (#612).
- `access_token_lifetime` above one hour is refused at load, as SMART App
  Launch 2.2.0, App Launch has access tokens live no longer (#604).
- FerroSMART authenticates to every upstream identity provider with
  `private_key_jwt` alone (OpenID Connect Core 1.0 §9).
  `[ferrosmart.upstream.private_key_jwt]` is required, and the keys
  `client_secret` and `client_secret_file` are gone from
  `[ferrosmart.upstream]`, so a configuration that names one is refused at
  load, as is a public upstream client. Each assertion names the provider's
  issuer as its sole `aud` and is typed `client-authentication+jwt`
  (RFC 10070 §4). The Okta example moves to a public key on the
  integration, the ZITADEL bootstrap to Private Key JWT with the
  application key ZITADEL generates, held under its key id, and the README,
  the architecture and the book describe all four providers in one shape:
  login, client authentication, `fhirUser`, roles and how each is tested
  (#619).
- The Keycloak example authenticates FerroSMART with `private_key_jwt`: the
  realm's client takes the `client-jwt` authenticator and reads
  FerroSMART's `{issuer}/upstream-jwks`, so `compose.keycloak.yaml` and the
  CI lanes make an `upstream_assertion_key` in place of a
  `keycloak_client_secret` (#569).
- The audit lane takes `ihe-atna` and `ehds-logging` 0.23. Their FHIR Feed
  sends through FerroSMART's own outbound client as a `FeedClient`
  (`audit_feed`), so FerroSMART links one copy of `ferrohealth-smart` with no
  `[patch.crates-io]` in the workspace (#549).

### Fixed

- A Backend Services access token lives at most five minutes, whatever
  `access_token_lifetime` says, as SMART App Launch 2.2.0, Backend
  Services, Issue Access Token has `expires_in` not exceed 300 (#603).
- A client assertion sent with a `client_id` other than its `iss` is
  refused with `invalid_client`, as SMART App Launch 2.2.0, Client
  Authentication: Asymmetric, Signature Verification requires (#601).
- An expired client assertion whose signature holds is refused as
  `invalid_client` with the description "the client_assertion has
  expired", told apart from one that does not verify (RFC 7523 §3). The
  examples of SMART App Launch 2.2.0 §9 run as test vectors (#609).
- The SMART configuration lists every capability FerroSMART supports and
  nothing else (SMART App Launch 2.2.0, Conformance, Capabilities): it adds
  `authorize-post`, `permission-offline`, `permission-online`,
  `context-standalone-patient` when the patient picker can search a
  resource server, and `context-style` when `[ferrosmart.branding]
  smart_style_url` is set. It names
  `token_endpoint_auth_signing_alg_values_supported` beside
  `private_key_jwt`, and `scopes_supported` lists the identity, launch
  context and refresh scopes FerroSMART honours (#600).
- The token endpoint answers a request from one of the client's registered
  origins, the origins of its redirect URIs, with
  `Access-Control-Allow-Origin` and `Vary: Origin`, so a browser app can
  read its token response (SMART App Launch 2.2.0, Considerations for CORS
  support). Every other origin gets no CORS header (#560).

[Unreleased]: https://github.com/FerroHEALTH/FerroSMART/compare/ferrosmart-v0.1.0...HEAD
[0.1.0]: https://github.com/FerroHEALTH/FerroSMART/releases/tag/ferrosmart-v0.1.0
