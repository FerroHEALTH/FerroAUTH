<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The changelog moves from the repository root to
  `crates/ferrohealth-smart/CHANGELOG.md`, beside `ferrohealth-authz`'s, and
  the published crate carries it.

## [0.7.0] - 2026-10-25

The granted subject: a caller's roles from the RFC 9068 claims or the Basic
user's configuration, with role requirements in the route table; the
assurance level and the natural person behind a token, with the RFC 9470
step-up; `OauthSection` checks named in the product's own keys and URLs
rendered without userinfo. The repository releases `ferrohealth-authz`
beside this crate, and each crate is now tagged with its name; this release
is `ferrohealth-smart-v0.7.0`. Products pin `=0.7.0`; the breaking change
below names what a product changes.

### Added

- The roles a caller holds (#101). `Caller::roles()` carries what the
  `roles`, `groups` and `entitlements` claims of RFC 9068 §2.2.3.1 hold, or
  the dotted paths `[auth] role_claims` names, from a JWT and from an
  introspection answer alike: each string array element, each SCIM complex
  element's `value` (RFC 7643 §2.4) and each word of a string, trimmed and
  once. A Basic user holds `[[auth.basic.users]] roles`
  (`PasswordStore::with_roles`). `Caller::has_role` matches without regard to
  ASCII case and `Caller::claim_text` reads a string at a dotted claim path.
- Role requirements in the route table: `Requirement::Role`,
  `Requirement::AnyRole`, `Requirement::WithoutRole` (a restriction that
  overrides a grant) and `Requirement::All`.
- RFC 7643 and RFC 9396 are vendored and pinned.
- `assurance` (#102): `AssuranceSection` maps the values of a token's
  authentication context class claim (`acr` by default) to the levels low,
  substantial and high, `assess` reads them, `meets` holds a caller to a
  minimum, and `step_up` gives the RFC 9470 §3 refusal naming the accepted
  `acr_values`. `ProfessionalSection` reads the natural person behind a
  token, telling a client token apart (`sub_is_client` by RFC 9068 §2.2, or
  `claim_absent`) and reading whom a client acts for. A Basic caller carries
  neither. Both sections validate at boot.
- `OauthSection::problems(table)` (#105): every problem of a grant without
  reading a file, each naming its key under the product's table, so a product
  reports a table it embeds at `terminology.server.oauth` in its own keys.

### Changed

- The repository releases a second crate, `ferrohealth-authz`, on its own
  version line (#103): its tag is `ferrohealth-authz-vX.Y.Z`, its changelog
  `crates/ferrohealth-authz/CHANGELOG.md`, and the release and publish lanes
  package, attest and publish the one crate a tag names. The release plan refuses a cut whose
  `[Unreleased]` link does not compare from the tag, and the link now
  compares from `v0.6.0`.

- Each crate is tagged with its name from this release on (owner decision
  of 2026-10-25): `ferrohealth-smart-vX.Y.Z` releases `ferrohealth-smart`,
  beside `ferrohealth-authz-vX.Y.Z`. The release lane, the release plan, the
  milestone check and the manual publish guard take the per-crate tags; the
  `v0.1.0` to `v0.6.0` tags stay and count as `ferrohealth-smart`'s earlier
  releases.

- An `OauthSection` renders `issuer` and `token_endpoint` with any userinfo
  masked, serialized and in `Debug` (#105); its `Debug` is written by hand.

- **Breaking:** `resource::Settings`, `resource::introspection::IntrospectionSettings`,
  `config::AuthSection`, `config::BasicUser` and `basic::Verified` gain a
  field (`role_claims` or `roles`); a struct literal adds it or ends with
  `..Default::default()` where the type has a default. `basic::StoreError`
  gains `Role` and `UnknownUser`.

- The repository is FerroAUTH, renamed from FerroSMART on 2026-10-25, at
  <https://github.com/FerroHEALTH/FerroAUTH>; the old address redirects. It
  holds two crates: authentication, `ferrohealth-smart`, and the policy
  decision, `ferrohealth-authz`. The `repository` and `homepage` fields of
  the published manifest name the new address. The crate name and every
  `ferrohealth_smart` path stay as they are, so a product changes nothing.

## [0.6.0] - 2026-10-25

Token introspection (RFC 7662) for an authorization server that issues
opaque access tokens: `resource::introspection::Introspector` beside the
JWT check, under the product's client authentication or a bearer token, with
a cache bounded by each response's `exp`, and `[auth] mode =
"introspection"` to configure it. Products pin `=0.6.0`; the breaking change
below names what a product changes.

### Added

- `resource::introspection`, behind the `fetch` feature: `Introspector`, a
  `Verifier` that checks a bearer token by OAuth 2.0 Token Introspection
  (RFC 7662) for an authorization server whose tokens the resource server
  cannot read itself, with `IntrospectionSettings`, `IntrospectionAuth` and
  `IntrospectionError`. The call authenticates with the client
  authentication of the token endpoint or with a bearer token from the
  client credentials grant (SMART App Launch 2.2.0, Token Introspection).
  `active` other than `true` refuses the token with the new
  `Reason::Inactive`; `scope`, `client_id` and `exp` are required; `iss`
  and `aud` are checked when present; the claims are read by the step the
  JWT check uses. An active response is held until its `exp` and at most
  `cache_max_age`, in a bounded cache keyed by the token's SHA-256. An
  endpoint that fails answers `503` (FerroBRIDGE #533).
- `[auth] mode = "introspection"` with the `[auth.introspection]` table
  (`endpoint`, `cache_max_age_seconds`, `cache_capacity`, and one of
  `client` and `bearer`), resolved into `Resolved::introspection`;
  `config::AuthMode`, `config::IntrospectionSection`, and the
  `ConfigError` variants `Introspection` and `IntrospectionUnavailable`.

### Changed

- **Breaking:** `config::AuthSection` gains `mode` and `introspection`, and
  `config::Resolved` gains `introspection` (with the `fetch` feature); a
  struct literal adds them or ends with `..Default::default()`.
- `Caller::cached` is also `true` for a bearer caller admitted from a held
  introspection response.

## [0.5.1] - 2026-10-25

A patch release with no breaking API change: the repeated-name refusal of
0.5.0 now covers the key set, operator-supplied metadata is compared and
checked through the same functions discovery uses, its mutual-TLS token
alias included, and the manual crate publish runs only at a released tag.
A product pins `=0.5.1` in place of `=0.5.0` and changes nothing else.

### Fixed

- `ResourceServer::with_metadata` holds the `mtls_endpoint_aliases`
  token endpoint (RFC 8705 §5) of operator-supplied metadata to the `https`
  rule of RFC 8414 §2 like every other location, so a plain-`http` alias is
  refused with `ResourceError::Discovery`; the check reads the members
  `ServerMetadata::endpoints` lists (#93).

### Changed

- A key set in which any object, at any depth, repeats a member name is
  refused with the new `ResourceError::KeySetRepeatedName`, as the metadata
  document is since 0.5.0, whether it is read over the `jwks_uri` or from a
  `jwks_file` (RFC 8259 §4). A held set stays in use for the keys it holds
  when a read is refused (#88).
- `ResourceServer::with_metadata` compares the issuer of operator-supplied
  metadata through `metadata::check_issuer`, the RFC 8414 §3.3 comparison
  discovery uses; the refusal stays `ResourceError::MetadataIssuer` (#89).
- The manual `Publish crates` workflow publishes only when it runs at the
  tag `v<version>` of the manifest version and a published GitHub release
  exists for that tag; any other run is refused before the `crates-io`
  approval, naming what is missing. The dry run is unchanged. 0.4.1 reached
  crates.io with no tag and no release that way (#91).

## [0.5.0] - 2026-10-25

`openehr-sdt` 0.0.98, the version FerroEHR v5.4.1 publishes, so FerroEHR
builds one copy of the SMART on openEHR parser, and three checks on the
authorization server metadata FerroPIX's Nuts grant kept privately: the
issuer compared as exact text, a document that repeats a member name
refused, and an opt-in check that every endpoint sits on the issuer's
origin. Products pin `=0.5.0`; the breaking changes below name what a
product changes.

### Added

- `metadata::check_issuer`, the RFC 8414 §3.3 comparison of the issuer a
  metadata document names with the one its location was built from, as
  exact text with no normalization (RFC 8414 §4), and
  `metadata::canonical_issuer`, which also holds a configured issuer to the
  canonical form the URL parser writes, without userinfo, for a product that
  wants the text compared and the URL fetched to have one meaning (#67).
- `ServerMetadata::check_origin`, an opt-in check that every endpoint the
  metadata names (`jwks_uri`, the authorization, token, registration,
  introspection and revocation endpoints and the mutual-TLS token alias)
  shares the issuer's scheme, host and port (RFC 6454 §4, §5), with
  `metadata::same_origin` for one location and `ServerMetadata::endpoints`
  listing them; `DiscoveryError` gains `EndpointUrl` and `OtherOrigin`
  (#68).
- `metadata::repeats_no_name` and `metadata::parse_metadata`, the reader of
  a metadata body that refuses one whose objects repeat a member name
  (RFC 8259 §4) (#69).

### Changed

- Discovery refuses a metadata document in which any object, at any depth,
  repeats a member name, with the new `DiscoveryError::RepeatedName`, so a
  second `issuer` or `jwks_uri` another parser would take cannot hide in it
  (RFC 8259 §4). A repeated member the crate reads was refused before as
  `DiscoveryError::Metadata`; it is now `RepeatedName`, so a product that
  matches on `Metadata` for that case matches the new variant (#69).
- The release checks the family's Security changelog rules: every
  `### Security` entry names a GHSA advisory or an OpenVEX statement under
  `security/vex/`, and a Security section beside other changes opens with
  "Shipped with functional changes because:" and its reason (Regulation (EU)
  2024/2847 Annex I Part II(2), (4), (8)). CI checks `[Unreleased]`, and the
  release `plan` job the section it cuts, through `scripts/release/plan.sh`,
  which `scripts/release/preflight.sh` replays before the tag
  (`docs/release.md`). The release notes state the month the five years of
  security fixes end (Art 13(19)). CI fails an advisory exception in
  `deny.toml` that no longer names a finding. `SECURITY.md` names the
  `info@cadasto.com` reporting route and the advisory each fixed
  vulnerability is published as (#72).
- `SECURITY.md` states the response times every product of the Ferro family
  states: an acknowledgement within about 5 business days in place of seven
  days, an initial assessment within about 10 business days, both best
  effort, and a fixed release published within 7 days of the confirmed
  assessment for a Critical vulnerability, 30 days for High, 90 days for
  Medium and with the next release for Low.
- **Breaking:** `openehr-sdt` 0.0.98 in place of 0.0.90, the version
  FerroEHR v5.4.1 publishes, so FerroEHR builds one copy of the SMART on
  openEHR parser in place of two. The `openehr::smart_scopes` re-export
  names the 0.0.98 types, so a product with the `openehr` feature that
  depends on `openehr-sdt` itself moves to 0.0.98 with it (#83).

## [0.4.1] - 2026-10-21

A patch release with no API change: a product pins `=0.4.1` in place of
`=0.4.0` and changes nothing else.

### Changed

- The crate declares `rust-version = "1.98"` in place of 1.97, and the
  repository builds with Rust 1.99.1 in place of 1.98.1: the FerroHEALTH
  family builds with the latest stable toolchain and declares the release
  before it as its MSRV. A product on a toolchain older than 1.98 can no
  longer take the crate.

## [0.4.0] - 2026-10-20

The gaps FerroFED's migration and FerroEHR's move to 0.3.1 found, closed in
the crate: a lazy resource server and a `Send` discovery future, a named
credential header for an edge proxy, a typed upstream failure for a product
verifier, mutual TLS and a product HTTP client for the token client, a
configurable assertion audience, the RFC 9470 step-up challenge, a typed
extension on the caller, a Basic user list helper, and the cache-hit signal
of a Basic check. Products pin `=0.4.0`; the breaking changes below name
what a product changes.

### Added

- `ResourceServer::lazy` and `LazyResourceServer`: the settings are checked
  at once and the issuer's metadata and key set are read when the first
  token needs them; a read that fails answers `503` and is not repeated
  inside `jwks_refresh_interval_seconds`. `IssuerSet::with_lazy` routes to
  one (#55).
- `guard::CredentialHeader` and `Gate::with_credential_header`: a product
  behind an edge proxy names the header the credential travels in, schemed
  like `Authorization` or bare, under the same rules; the default stays
  `Authorization`. `Gate::credential` returns the credential text the gate
  read (#56).
- `resource::Rejection::Upstream` and `Rejection::upstream`: a product
  verifier reports an upstream failure (an RFC 7662 introspection
  endpoint) with its own error as the source; it answers `503` with
  `Reason::UpstreamUnavailable` (#57).
- Mutual TLS for the token client (RFC 8705): `ClientAuth::TlsClientAuth`
  and `ClientAuth::SelfSignedTlsClientAuth` (`tls_client_auth`,
  `self_signed_tls_client_auth`), `ClientCredentials::with_mutual_tls`,
  `client::Tls` with extra trust roots and the client certificate,
  `metadata::Http::with_tls` and `Http::from_client`,
  `TokenSource::with_http` for a product's own `reqwest::Client`, the
  `mtls_endpoint_aliases.token_endpoint` of RFC 8705 §5 used when a
  certificate is configured, and the `[<lane>.credentials.oauth]` keys
  `ca_file`, `client_certificate_file` and `client_key_file`, read and
  parsed at load (#58).
- `client::AssertionAudience` and `[<lane>.credentials.oauth]
  assertion_audience`: the `private_key_jwt` assertion names the token
  endpoint (the default, SMART's rule) or the issuer identifier (RFC 7523
  §3) (#59).
- The RFC 9470 step-up challenge: `refusal::StepUp` with `acr_values` and
  `max_age`, `Refusal::StepUp` answering `401` with
  `error="insufficient_user_authentication"`, `StepUp::satisfied_by`, and
  `Caller::acr` and `Caller::auth_time`. RFC 9470 joins the vendored set
  (#60).
- A typed extension on the caller: `ResourceServer::with_extension`,
  `LazyResourceServer::with_extension` and `Caller::with_extension` attach a
  product value, `Caller::extension` and `Access::extension` read it, so a
  product's per-issuer policy travels with the verified caller. Equality on
  `Caller` ignores extensions (#61).
- `Caller::basic_user_in`, `Access::basic_user_in` and
  `Requirement::basic_users`: whether a Basic caller is one of a list of
  user-ids; a bearer subject never matches (#62).
- `basic::Verified::cached` and `Caller::cached`: whether a Basic credential
  was admitted from the verified-credential cache, so a product records one
  fresh authentication per cache lifetime (#63).

### Security

- `rustls-webpki` 0.103.16 and `webpki-root-certs` 1.0.10 in the lock, past
  RUSTSEC-2026-0382 and RUSTSEC-2026-0383 (certificate paths through the
  distrusted emSign intermediates) (#66).

### Changed

- `ResourceServer::discover` returns a `Send` future, so a product calls
  it from a request without a blocking thread (#55).
- **Breaking:** `client::ClientCredentials` gains the public fields
  `assertion_audience` and `tls`, and `config::OauthSection` gains
  `assertion_audience`, `ca_file`, `client_certificate_file` and
  `client_key_file`; a struct literal adds them or uses a constructor or
  `..Default::default()` (#58, #59).
- **Breaking:** `client::ClientAuth` gains two variants, so an exhaustive
  `match` adds `TlsClientAuth` and `SelfSignedTlsClientAuth` (#58).
- **Breaking:** `metadata::ServerMetadata` gains
  `mtls_endpoint_aliases`; a struct literal adds it or ends with
  `..ServerMetadata::default()` (#58).
- **Breaking:** `basic::Verified` gains the public field `cached` (#63).

## [0.3.1] - 2026-10-20

`openehr-sdt` 0.0.90, the version FerroEHR publishes. No public API changes;
products pin `=0.3.1`.

### Changed

- `openehr-sdt` 0.0.90, the version FerroEHR publishes, so a product and
  the crate resolve one copy of the SMART on openEHR parser behind the
  `openehr::smart_scopes` re-export (#52).

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

[Unreleased]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.7.0...HEAD
[0.7.0]: https://github.com/FerroHEALTH/FerroAUTH/compare/v0.6.0...ferrohealth-smart-v0.7.0
[0.6.0]: https://github.com/FerroHEALTH/FerroAUTH/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/FerroHEALTH/FerroAUTH/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/FerroHEALTH/FerroAUTH/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/FerroHEALTH/FerroAUTH/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/FerroHEALTH/FerroAUTH/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/FerroHEALTH/FerroAUTH/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/FerroHEALTH/FerroAUTH/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/FerroHEALTH/FerroAUTH/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/FerroHEALTH/FerroAUTH/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/FerroHEALTH/FerroAUTH/releases/tag/v0.1.0
