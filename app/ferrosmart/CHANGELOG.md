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
