<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-10-20

The gaps FerroEHR's migration found, closed in the crate: a blank `sub` is
refused, the configuration sections render with every secret redacted, a
Basic-only `[auth]` resolves, a `jwks_file` issuer takes operator-supplied
metadata, the SMART on openEHR requirement honours `scopeless_subjects`,
`Requirement::Client` admits named Basic principals, verified Basic
credentials are cached, a bearer value outside `b64token` is refused, the
product reads the reason of every refusal, and the SMART on openEHR grammar
is re-exported. Products pin `=0.3.0`; the breaking changes below name what
a product changes.

### Added

- `Serialize` on `config::AuthSection`, `IssuerKey`, `IssuerEntry`,
  `BasicSection`, `BasicUser`, `CredentialsSection` and `OauthSection`, so
  a product renders its running configuration. `password_hash`, `password`
  and `client_secret` are written as `[redacted]`, never their value; a
  `_file` path is written as configured (#42).
- A Basic-only surface: an enabled `[auth]` section with
  `[[auth.basic.users]]` and an empty flat `issuer` resolves to no issuer
  and the Basic store, so a product needs no `enabled = false` workaround
  (#43).
- `ResourceServer::with_metadata`: operator-supplied `ServerMetadata` for a
  `jwks_file` issuer, held to the configured issuer (RFC 8414 §3.3) and the
  `https` rule (RFC 8414 §2), so its SMART discovery document names a
  `token_endpoint`. `resource::configuration::document` is public (#44).
- `Caller::scopeless()`, whether the subject is on `[auth]
  scopeless_subjects` (#45).
- `[auth.basic] cache_ttl_seconds` and `PasswordStore::with_cache`: a
  verified Basic credential is kept for the TTL under an HMAC of the
  credential, so a repeat request skips the key derivation; 0 (the
  default) keeps none (#47).
- `refusal::Reason` and `refusal::Denied`: the check that refused a
  credential, for the product's own log. The wire answer stays the bare
  `invalid_token` of RFC 6750 §3 (#47).
- `openehr::smart_scopes`, the SMART on openEHR grammar module of
  `openehr-sdt` re-exported, so a product names `SmartScope`,
  `ResourceFamily` and `Permission` through the crate and links one copy of
  the parser (#48).

### Changed

- **Breaking:** `guard::Gate::authenticate` returns `Result<Access,
  Denied>`. `Denied::refusal()` is the refusal it returned before and
  `Denied::reason()` names the failed check; `Refusal::from(denied)` and
  `denied.into_refusal()` give the refusal alone (#47).
- **Breaking:** `config::BasicSection` gains the public field
  `cache_ttl_seconds`, so a struct literal adds it or ends with
  `..BasicSection::default()` (#47).
- **Breaking:** `resource::Rejection::Invalid { reason }` carries a
  `refusal::Reason` in place of a `&'static str`. A product's own
  `Verifier` names its reason as `Reason::Other("…")` (#47).
- **Breaking:** `guard::Requirement::Client` is a struct variant,
  `Client { client_ids, basic_users }`: a listed bearer `client_id` or a
  listed Basic user-id meets it, each list matched only against its own
  scheme. `Client(ids)` becomes `Client { client_ids: ids, basic_users:
  vec![] }` (#46).
- **Breaking:** `Requirement::OpenEhr` admits a caller on `[auth]
  scopeless_subjects` whose token carries no resource scope of either
  grammar. With the `openehr` feature a SMART on openEHR resource scope
  counts as a scope on a FHIR route too, so an allowlisted subject whose
  token carries only `system/composition-*.r` no longer reaches every FHIR
  resource (#45).
- A bearer value outside the RFC 6750 §2.1 `b64token` syntax is refused as
  `invalid_token` before the verifier reads it (#47).
- `openehr-sdt` stays at 0.0.89, the newest version on crates.io (#48).

### Fixed

- A token whose `sub` is empty or whitespace only is refused with the
  generic `invalid_token` (RFC 9068 §2.2, RFC 7519 §4.1.2), by the token
  check and by the gate over any `Verifier` (#41).
- An enabled `[auth]` section that admits no credential at all, such as
  `issuer = []` without Basic users, is refused at load with
  `ConfigError::Missing { key: "auth.issuer" }`; it resolved before and
  left the product an open gate (#43).
- `guard::Requirement::met_by` lints clean in the `axum` build without
  `openehr`, which CI now lints too.

## [0.2.0] - 2026-10-20

The gaps FerroTERM's migration found, closed in the crate: the SMART
discovery document claims only the permission capabilities a product
declares and writes `issuer` only with `sso-openid-connect`, a refusal's
renderer reads the request head so a product negotiates JSON or XML, and
the HTTP fetchers sit behind the default `fetch` feature. Products pin
`=0.2.0`; the breaking changes below name what a product changes.

### Added

- The `fetch` feature, on by default, carries the HTTP fetchers: the
  issuer's metadata, the key set over its `jwks_uri` and
  `client::cache::TokenSource`. A product built with
  `default-features = false` links no `reqwest` and reads its key set from a
  `jwks_file`; `ResourceServer::discover` then refuses settings without one
  with `ResourceError::KeySetFileRequired` (#38).
- `resource::configuration::PermissionCapability` and
  `SmartOptions::permissions`: the product declares the permission
  capabilities its route table enforces (#36).
- `resource::configuration::OpenIdConnect` and
  `SmartOptions::openid_connect`: whether the discovery document advertises
  `sso-openid-connect`, derived from an `openid` scope in the issuer's
  `scopes_supported` by default, declared, or withheld (#35).

### Changed

- **Breaking:** the SMART discovery document claims no permission
  capability unless the product declares it. `permission-v1`,
  `permission-patient` and `permission-user` were always written, and
  `SmartOptions::granular` is replaced by `PermissionCapability::V2` in
  `SmartOptions::permissions`. A product lists the capabilities its routes
  enforce (SMART App Launch 2.2.0, Conformance, Capabilities) (#36).
- **Breaking:** `issuer` is written only with `sso-openid-connect`, which
  SMART App Launch 2.2.0 (Conformance, Metadata) requires and which it
  otherwise omits. `sso-openid-connect` is written only when the issuer's
  metadata names a `jwks_uri`, which the capability also requires (#35).
- **Breaking:** `guard::Render::render` receives the refused request's head
  (`http::request::Parts`) beside the refusal, so a product answers in the
  format the request's `Accept` or `_format` negotiates. A renderer closure
  takes `(&Refusal, &Parts)`; `extract::HeaderOnly` ignores the head (#37).
- Without the `fetch` feature, `metadata::Http` and the
  `DiscoveryError::Build` and `DiscoveryError::Transport` variants are
  absent (#38).

## [0.1.1] - 2026-10-20

The gaps FerroBRIDGE's migration to 0.1.0 found, closed in the crate so no
product carries a copy: the Basic password readable as a secret, the audit
line's `addressed` field, the client credentials grant checked at load, a
product scope and validated capabilities in `[auth]`, and
`scopes_supported` in the SMART discovery document. Products pin
`=0.1.1`; the audit field rename and the new `[auth]` fields are the
changes a product makes.

### Added

- `basic::Credential::password` returns the password of an outgoing Basic
  credential as `&SecretString`, for an HTTP client that takes the user-id
  and the password itself; its `Debug` stays redacted (#27).
- `[auth] product_scope`: the product's own scope, a full URI or a string
  starting with `__` (SMART App Launch 2.2.0, Scopes and Launch Context,
  Extensibility), refused at load in any other form and resolved to
  `Resolved::product_scope` (#30).
- `scope::is_scope_token` (the RFC 6749 §3.3 scope-token rule) and
  `scope::is_extension_scope` are public, so a product checks its own
  scopes with the crate's rule instead of a copy (#30).
- `[auth] scopes_supported` and `Resolved::smart_options`: the scopes the
  product honours reach `scopes_supported` of the SMART discovery document,
  which "the server SHALL support" (SMART App Launch 2.2.0, Conformance,
  Metadata); each is checked as one scope token at load (#31).
- `resource::configuration::SMART_CAPABILITIES` and `is_capability`.

### Changed

- **Breaking for consumers of the audit log:** the audit line's `target`
  field is renamed `addressed`, and `audit::MAX_TARGET_LENGTH` is
  `MAX_ADDRESSED_LENGTH`. A JSON formatter that flattens the event fields
  wrote the field and the `tracing` target under one key, so a reader kept
  only one. A log query or dashboard that reads `target` for the addressed
  resource reads `addressed` (#28).
- `[auth] capabilities` refuses at load a value that SMART App Launch 2.2.0
  (Conformance, Capabilities) and the SMART on openEHR draft do not define
  and that is no full URI (#30).
- `[<lane>.credentials.oauth]` refuses at load an `issuer` outside the RFC
  8414 §2 URL rule, which was applied only at the first token request, and
  a `resource` with a fragment (RFC 8707 §2) (#29).
- `openehr-sdt` 0.0.89, the line FerroEHR v5.0.0 publishes (#22).
- `SECURITY.md`: only the newest release is supported. An earlier release
  receives no fix; upgrade to the newest release, which is free. Cadasto B.V.
  publishes security fixes for at least five years after each release (CRA
  Art 13(8)) and ships them only in the newest release (Art 13(10)).

## [0.1.0] - 2026-10-19

The first release: the shared SMART App Launch 2.x and OAuth 2.0
resource-server crate of the FerroHEALTH products, built to
`docs/architecture.md` from the FerroBRIDGE implementation, and the
repository setup. FerroSMART is a library, never an authorization server:
it issues no token and holds no key that signs one.

### Added

- `metadata`: the issuer's metadata read at the RFC 8414 §3 location, with
  the OpenID Connect Discovery 1.0 §4 location as the fallback on a `404`,
  the document's `issuer` required to match (RFC 8414 §3.3), the issuer and
  the `jwks_uri` held to `https` without a query or fragment (a loopback
  issuer may be plain `http`), and a 1 MiB ceiling on every document.
- `resource`: the resource server. The key set is read at boot, read again
  past its maximum age and once per interval on an unknown `kid`, a failed
  read keeps the held keys and is not repeated inside the interval, a
  member whose `use` is not `sig` or whose `key_ops` lack `verify` verifies
  nothing, and a token without a `kid` verifies only when the set holds one
  candidate. A token is checked under RFC 9068 (`typ` of `at+jwt`, the
  asymmetric algorithms of the configured list, `iss`, one of the
  configured audiences, `exp`, `nbf` and `iat` within a clock skew of at
  most 300 seconds, the required claims) or, by configuration, under a
  `jwt` profile for an issuer that mints no RFC 9068 token, where `scp` is
  read when `scope` is absent. A key set file replaces discovery for keys
  handed over out of band. `Verifier` is the seam a product plugs another
  check into, and `IssuerSet` routes each token to its trusted issuer. The
  SMART discovery document is built from the metadata with the options the
  product adds.
- `scope`: the SMART App Launch 2.2.0 scopes, `patient/`, `user/` and
  `system/` with the in-order `cruds` permissions, the v1 suffixes mapped
  as the specification has servers read them, the wildcard, the union rule,
  the patient compartment from the token's `patient` claim, the resource
  type held to the product's table, and the granular `?param=value`
  constraint carried on the grant and admitted only through a product
  evaluator.
- `openehr`, behind the `openehr` feature: the SMART on openEHR grammar
  beside the FHIR one, parsed by `openehr-sdt` and enforced here with the
  rules the draft leaves to the resource server: the permission letters in
  any order, `*` within a `::` segment and `**` across them, an operation
  naming no resource covered only by a bare wildcard, `system/aql-*` only
  for a listed backend client, a `patient/` grant only for a bound issuer
  and only on EHR data, no FHIR v1 suffixes, and both grammars in one
  `scope` claim; `Caller::ehr_id` and `Access::ehr_id` read the launch
  context's `ehrId`; the discovery document takes a platform's `services`
  map and the openEHR capabilities through `SmartOptions::with_openehr`.
- `basic`: HTTP Basic (RFC 7617) verified against a store of Argon2id PHC
  hashes with the enumeration decoy, each user carrying the scopes its
  configuration grants, and the outgoing credential that redacts itself.
- `client`: the OAuth 2.0 client credentials grant (RFC 6749 §4.4) with
  `client_secret_basic`, `client_secret_post` and `private_key_jwt` (the
  RFC 7523 assertion with the SMART asymmetric profile's header and claims,
  the `kid` configured or the RFC 7638 thumbprint, and the product's public
  JWK Set), the token endpoint configured or discovered, the cache with its
  refresh margin and shared fetch, and `call`, which sends a request once
  more under a new token when the upstream answers `401`.
- `audit`: one line per request under `ferrohealth_smart::audit` with the
  fixed fields `at`, `request_id`, `principal`, `client`, `via`, `issuer`,
  `method`, `route`, `target`, `interaction`, `status`, `duration_ms` and,
  on a batch entry, `entry`.
- `refusal`: the one `401` naming no claim (`invalid_token`), the `400` of
  two credentials or a malformed value (`invalid_request`), the `403`
  naming no scope (`insufficient_scope`), the `503` of an unreadable key
  set, and the Basic challenge with its realm and `charset="UTF-8"`.
- `config`: the `[auth]` section (the flat issuer or `[[auth.issuer]]`
  entries, the audiences, the algorithms, the profile, the skew and key
  set bounds, `jwks_file`, the realm, the scopeless subjects, the
  capabilities and the `[[auth.basic.users]]` with `password_hash` or
  `password_hash_file` and their scopes) and the `[<lane>.credentials]`
  table (`user` and `password` or `password_file`, or `oauth` with its
  `client_auth`, the secret or the `private_key_file`, `kid` and
  `assertion_alg`), every secret with its `_file` sibling of which exactly
  one is set, resolved at load.
- The `axum` feature: `guard`, the tower layer with the product's
  classifier (`Requirement::Public`, `Caller`, `Fhir`, `OpenEhr`, `Scope`,
  `Client`, `Either` or `Refused` on a `Target`), the credential check, the
  per-route permission check under the grammar the route declares with the
  product's `Honoured` flags, and the audit line, with the body of a
  refusal the product's; `extract`, the `Access` extractor and the
  header-only renderer.
- The repository setup as FerroUI's: the lint set, CI with the single
  required `conclusion` job, the vendored-specification guard, CodeQL,
  Scorecard, Dependabot, the release lane with signed tags and crates.io
  Trusted Publishing, the crate-version guard, the comment-style and
  `TODO(#N)` guards, the issue and pull request templates, the labels, the
  rulesets and the `crates-io` environment.

[Unreleased]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/FerroHEALTH/FerroSMART/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/FerroHEALTH/FerroSMART/releases/tag/v0.1.0
