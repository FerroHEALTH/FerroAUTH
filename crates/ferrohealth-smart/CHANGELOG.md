<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The `test-support` feature, for a downstream crate's tests only:
  `federation::External::new` builds the party that
  `CallerKind::ExternalPerson` and `ExternalOrganisation` carry, so a
  policy over the two external kinds can be tested without a `federation`
  token (#272). It runs none of the classification's checks, and a product
  never enables it outside its tests.

## [0.9.0] - 2026-11-06

The caller classification (#215) and the party binding (#216). This
release breaks the public configuration and API: every product moves its
`[auth]` section to the issuer tables below and reads who called from
`Caller::kind`.

### Added

- `kind::CallerKind`, read through `Caller::kind`: who stands behind a
  credential, `Patient`, `System`, `Delegated` (with the RFC 8693 actor
  when there is one), `Representative` (the represented subject and the
  ground as asserted), `Person` or `Guest` wrapping the kind it would
  otherwise have. A valid token that matches no step for its issuer's kind
  is refused as `Rejection::Unclassified`, an `invalid_token` on the wire
  whose `kind::Unclassified` reason names the step. The audit line records
  the kind in its new `kind` field.
- `kind::IssuerKind` and the required `kind` key of every
  `[[auth.issuer]]`: `persons`, `patients`, `machines` or `federation`.
  A `federation` issuer needs its one `[[auth.federation]]` table
  (`ConfigError::Federation` otherwise).
- `federation`: what a `federation` issuer asserts about another party.
  `[[auth.federation]]` (`FederationSection`) maps each field, named after
  the 2026/2099 Annex Tables 1 and 2, to a claim path (`mapping = "iua"`
  for the IHE IUA claims), a constant, an attested RFC 9396
  `authorization_details` entry whose `locations` names this node, or a
  Nuts RFC021 presentation. `CallerKind::ExternalPerson` and
  `ExternalOrganisation` carry the `External` fields as asserted and the
  remote `sub`, never bound. A partial professional is refused naming the
  missing fields; the declared countries, issuing authorities and provider
  identifier prefixes bound every attribute; a control or bidi-control
  character, two disagreeing sources and a professional below level
  substantial are refused. Strings are compared exactly (RFC 9396 §12).
- `federation::contact`: the MyHealth@EU contact-point profile. A
  `contact_point = true` issuer (`mapping = "ehdsi"`) requires
  `sender_constraint = "required"` and fails to load without it
  (`ResourceError::ContactPointSender`, #220), takes no provider prefixes,
  and configures its country and issuing authority. Its tokens carry the
  eHDSI SAML Profile 10.0.0 §2.3 attributes, and each refusal carries its
  Requirements Catalogue 10.0.0 §1.25 code name (`EhdsiCode`,
  `Unclassified::ContactPoint`); `EhdsiCode::of` names any rejection, an
  unreadable key set or upstream as `ERROR_SEC_GENERIC` (requirement 11),
  since §1.25 gives that case no code of its own (#238). A
  token never outlives the identity assertion or the TRC window, any of
  the seven authentication classes is admitted and recorded, and nothing
  is refused on the description, the role or the point of care.
- `profile = "nl"` (#238): the harmonised BgZ and eOverdracht
  authentication of the openEHR Federation Tier specification 1.0.1 Annex
  B §B.4a, for a `federation` issuer that is one requesting care provider.
  Its `nl-gis-v1` `authorization_details` entry is attested and is the
  organisation's access statement; `purpose_of_use` and
  `nl.organisation_type` are read from it, and the deployment configures
  the issuer's `nl.ura`. The issuer requires `sender_constraint =
  "required"` and its own `token_types`, and a token missing the purpose,
  the organisation type or the URA is refused as
  `Unclassified::RequiredFields`. Every value cites its Annex B section.
- A preset file may carry `[[auth.federation]]` defaults
  (`Preset::federation`), which the issuer's own table is set over
  (`FederationSection::over`); an issuer of another kind refuses them. The
  federation table gains `required_fields`, the fields every token must
  carry, and `requires_sender_constraint`, which refuses the issuer without
  `sender_constraint = "required"` (`ResourceError::SenderConstraintRequired`).
- `profile`: each issuer's `Profile`, a `Preset` (`profile = "rfc9068"`,
  `"entra"`, `"keycloak"`, `"okta"` or `"nl"`, shipped as `profiles/*.toml` with
  each value labelled by its source) with any profile key set over it on
  the issuer table: `person_key`, `tenant_claim`, `client_claims`,
  `app_only`, `guest`, `impersonation_marker`, `expect`, `user_claims`,
  `person_equality`, `unstable_claims`, `first_party_clients`,
  `delegates`, `max_actor_chain`, `representation`, `token_types`,
  `required_claims`, `scope_claim`, `app_only_scope_claim` and `adapter`.
  A profile naming an adapter refuses its issuer, since this build
  compiles none. `email`, `phone_number`, `preferred_username` and `name`
  are never accepted as an identifier (OpenID Connect Core 1.0 §5.7).
- `Caller::person_key`, `Caller::tenant` and `Caller::assurance`.
- The `keycloak` preset documents how to mark an impersonation: map the
  `IMPERSONATOR_ID` session note into a claim with a User Session Note
  mapper and name that claim in `impersonation_marker`; the preset names
  none. The `okta` preset cites the page as re-pinned on 2026-11-05.
- `IssuerSet::with_introspector`: one set verifies JWT and introspected
  issuers together, routing a token with a readable `iss` to its issuer
  and an opaque token to the one introspected issuer.
- `config::Resolved::check_role_issuers`, which refuses a product's
  administrator, emergency or identifier-reader role list naming an
  issuer that is not a trusted `persons` issuer.
- `sender`: sender-constrained tokens (#220), bound to a DPoP key
  (RFC 9449) or to the client certificate of the mutual-TLS connection
  (RFC 8705 §3). Each `[[auth.issuer]]` takes `sender_constraint`,
  `"none"` by default or `"required"`, under which only a token whose
  `cnf` names a `jkt` or an `x5t#S256` is admitted. On every issuer a
  token that carries `cnf` is held to it and is never accepted as a plain
  bearer token, and a `cnf` naming any other method is refused. Each
  refusal is a `Rejection::Invalid` whose `Reason::Sender` names the
  failed `sender::Check`.
- `sender::proof::ProofCheck`, every check of RFC 9449 §4.3 over the
  `DPoP` header of a `DPoP` request, with the `htu` compared with the
  configured external base URL plus the request path. The `[auth.dpop]`
  table (`external_url`, `max_age_seconds` 60, `clock_skew_seconds` 10,
  `algorithms`) resolves to `Resolved::dpop`, and `Gate::with_dpop`
  admits the `DPoP` scheme. A refused proof answers
  `DPoP error="invalid_dpop_proof"`, a refused `DPoP` token
  `DPoP error="invalid_token"`, and a missing credential is challenged
  with `DPoP` beside `Bearer`.
- `sender::replay::ReplayStore`, the product's store of accepted proof
  `jti`s (RFC 9449 §11.1), and `MemoryReplayStore`, its in-memory
  default, which refuses a replay to the process that saw the proof
  alone. A product that runs more than one replica supplies a store they
  share. A store that fails answers `503`.
- `sender::ClientCertificate`, which a product puts in a request's
  extensions for the gate to hold a certificate-bound token to;
  `Verifier::verify_bound`, `ResourceServer::authenticate_bound`,
  `LazyResourceServer::authenticate_bound`,
  `Introspector::authenticate_bound` and `Gate::authenticate_request`.
- `client::onward`, the onward grants (#217): `exchange::Onward` obtains a
  token for another service on behalf of a verified caller, by RFC 8693
  token exchange (`subject_token`, an optional `actor_token`, the target as
  `resource` or `audience`) or the RFC 7523 JWT bearer grant (`assertion`
  and `scope`), as the issuer's profile names, authenticating as its
  `ClientCredentials` say. The issued token is refused unless its `iss` is
  the issuer asked, its `aud` lies inside the `Target`'s audiences, its
  `exp` is within `max_onward_lifetime` of its `iat`, it carries the
  profile's `expect`, it names the requesting client as its actor, and it
  names the caller's person: by `person_equality` on a `persons` issuer, by
  the attested `person_mapping` on a `federation` issuer. Every refusal is
  a typed `OnwardError`, an upstream refusal with its status and
  `interaction_required` with its claims challenge; a JWT bearer grant for
  a `System` caller is refused before sending (`UserPrincipalRequired`),
  `offline_access` is never sent and a refresh token never accepted. The
  token is cached by issuer, grant, subject and actor token, target, scope
  and extra parameters until a margin before the earlier of its own and the
  subject token's `exp`, and the check runs again on every hit.
- The profile keys `max_onward_lifetime`, `onward_grant`,
  `onward_indicator`, `onward_parameters`, `onward_client_id`,
  `onward_subject_audience` and `onward_preview` (`profile::onward`), on
  `[[auth.issuer]]` as on every preset: `entra` is the on-behalf-of flow,
  `keycloak` the standard token exchange with delegation refused as
  Preview. A parameter the client writes itself, a `requested_token_type`
  naming a refresh token and a lifetime of 0 refuse the issuer at load.
- `exchanges_from` and `person_mapping` on `[[auth.federation]]`, which a
  federation issuer of onward tokens requires.
- `[<lane>.credentials.onward]` (`config::onward::OnwardSection`, #246):
  the onward target of a lane, with the issuer of its onward tokens
  described in the table (`issuer`, `kind`, `profile`, `[onward.keys]`,
  `[onward.federation]`, `[onward.assurance]`), its `audiences`,
  `indicators`, `scope` and `correlation_claim`, and an optional
  `token_endpoint` and `client_id`. It authenticates with the lane's
  `oauth` table, so its secret or key comes through the same `_file`
  keys. `CredentialsSection::onward` resolves it into an
  `config::onward::OnwardLane` (the `Onward` client and its `Target`) and
  refuses at load a table missing `issuer`, `kind` or `audiences`, beside
  a Basic `user` or without `oauth`, a profile its issuer's rules refuse,
  an issuer the onward client refuses (`ConfigError::Onward`) and a target
  its grant cannot ask for. `Onward::check_target` runs the target checks
  on their own.

- `party`: the party a person's login belongs to (#216). One
  `[[auth.party]]` table (`party::config::PartySection`) per `persons`
  issuer names the `identifier_issuer` and `identifier_type` its logins are
  matched against, and the `group_claim` and `group_identifier_issuer` its
  groups are read under; it has no `claim` key, since the issuer profile's
  `person_key` is the key, and `guests = true` looks a guest up. The product
  implements `party::source::PartySource` over its own store, and
  `party::binding::PartyBinding::resolve` looks a `Person`, `Delegated` or
  `Representative` caller, or a Basic user by the key
  `PartyBinding::with_basic_user` maps it to, up on every request, with no
  cache, into one `party::Outcome`: `Party` (the reference, the identifier
  that matched, the markers, the groups the token names that the party
  belongs to, its representation relationships, provisional and guest),
  `WrongMarker`, `Unbound`, `Ambiguous`, `Inactive`, `Abandoned`,
  `Deprovisioned`, `KeyClaimMissing` or `GroupsUnavailable`. `Patient`,
  `System` and external callers are never looked up. A failing source is a
  `SourceError`, never `Unbound`. A key of the `guid` or `uuid` type is
  compared in lower case.
- `party::adapter::IdpAdapter`, the vendor adapter seam a profile's
  `adapter` names: on a groups overage marker (`_claim_names` naming the
  group claim, or `hasgroups = true`) the adapter registered with
  `PartyBinding::with_adapter` is called before the outcome is decided, and
  its failure is `GroupsUnavailable` carrying the upstream status and
  `Retry-After` (`party::adapter::AdapterError`).
- `Gate::with_party`: the guard looks every admitted caller up and leaves
  the outcome on it (`Caller::party`, `Access::party`); a failing source
  answers `503`. `Caller::with_party` attaches an outcome a product
  resolved itself, and `PasswordStore::users` lists the Basic users, which
  `PartyBinding::check_basic` holds to a key each.
- The audit line records what the login resolved to in its new `binding`
  field (`source_unavailable` when the source failed, `-` when not looked
  up) and the party reference in `party`, never a party attribute.
- `ConfigError::Party`, naming an `[[auth.party]]` table that sets `claim`
  (with the profile's `person_key`), names no trusted `persons` issuer,
  shares its issuer or its `identifier_issuer` with another table (naming
  both), or sets `group_claim` without `group_identifier_issuer`.
- The `idp-entra` feature and `idp::entra::GraphAdapter` (#221): an Entra
  ID groups overage (`_claim_names` naming `groups`, or `hasgroups`) is
  resolved through Microsoft Graph at
  `{base_url}/users/{oid}/getMemberObjects`, or
  `/servicePrincipals/{oid}/getMemberObjects` for an `idtyp` of `app`,
  built from the token's `oid` and `idtyp` and never from
  `_claim_sources`, under a client-credentials token. An issuer turns it on
  with `adapter = "idp-entra"`; the product builds it from an
  `idp::entra::GraphSection` (`base_url`, `timeout_ms` of 2000 by default,
  `max_response_bytes`, `security_enabled_only`, `credentials`) and
  registers it under `idp::entra::NAME`. Every Graph failure is
  `GroupsUnavailable` with the status and the `Retry-After` of a `429`,
  the timeout, or the unreadable cause; nothing is cached, and each
  request of a user above the overage limit costs one Graph round trip
  outside the product's lookup budget. `idp::COMPILED` lists the adapters
  a build compiles in, and a profile naming any other adapter fails to
  load, naming it (`ProfileError::Adapter`).
- `AdapterError::Claim`: the token lacks or misforms a claim the adapter
  reads, and nothing was called.
- `AdapterError::Status` carries `body`, a `party::adapter::BodyExcerpt` of
  the error body the identity provider answered with (#261), which its
  message ends with: at most 256 characters, control characters as spaces,
  and every string and number of the caller's token claims, the subject and
  every compact JWS replaced by `***`. The Graph adapter reads the body of
  every refusal up to `max_response_bytes`; a body it cannot read leaves
  the status and no excerpt. An adapter of a product's own builds the
  excerpt with `BodyExcerpt::new`.

### Changed

- Every issuer setting lives on its own `[[auth.issuer]]` table, with no
  section-level fallback: `audience`, `algorithms`, `clock_skew_seconds`,
  `jwks_max_age_seconds`, `jwks_refresh_interval_seconds`, `jwks_file`,
  `timeout_ms`, `mode`, `introspection` (now `[auth.issuer.introspection]`),
  `role_claims` and the new `assurance` table. Upgrade: move each key onto
  every issuer table it held for; a section-level key fails to load naming
  the table (`ConfigError::Removed`).
- `scopeless_subjects` entries are tables, `{ issuer, sub }`, and admit only
  a `System` caller of that issuer. Upgrade: rewrite each string, bare or
  `<issuer>#<sub>`, as a table; a string fails to load.
- A Basic credential is always a `CallerKind::Person`, never a `System`:
  a machine authenticates with the client credentials grant (RFC 6749
  §4.4). Upgrade: move each machine on Basic to a client credentials
  client of a `machines` or `persons` issuer.
- `Caller::is_the_person` holds for a `Patient` caller alone: a token of a
  `patients` issuer whose scopes are `patient/` with no `user/` or
  `system/` grant. A `persons` token whose only clinical scopes are
  `patient/` is a professional confined to its launch context. Upgrade:
  give patients and professionals separate issuers (a realm or tenant
  each), the patients' with `kind = "patients"`.
- A `persons` token is admitted only through a client the issuer lists in
  `first_party_clients` or `delegates`. Upgrade: list the deployment's own
  clients in `first_party_clients`.
- `Caller::client_id` is the client the profile's `client_claims` name
  (`client_id` by default, `azp` under `entra` and `keycloak`, `cid` under
  `okta`).
- `Caller::new` and `resource::Settings::new` take the kind, and
  `introspection::IntrospectionSettings::new` takes the kind after the
  authentication; `Resolved::introspection` is a list, one entry per
  introspected issuer; `assurance::AssuranceSection::assess` reads a
  token's claims, and `meets` the caller's assessment.
- An introspection response with `token_type = "DPoP"` is admitted when
  it names a `cnf.jkt`, and checked against the `DPoP` request's proof;
  one that names a `jkt` under `Bearer`, or `DPoP` without a `jkt`, is
  refused. A held response is checked against each request's binding.
- `refusal::Schemes` has a `dpop` field and `Refusal` the
  `InvalidDpopToken` and `InvalidDpopProof` variants. Upgrade: a product
  that builds `Schemes` sets `dpop: false`, and a product that matches
  `Refusal` exhaustively answers both with the challenge the crate
  renders. `Gate::authenticate` reads no request line, so it refuses a
  `DPoP` request and a certificate-bound token; the layer uses
  `Gate::authenticate_request`.
- The workspace requirement on `ferrohealth-smart` moves to 0.9.0.
- `audit::Actor::Caller` carries `binding` and `party`, and the audit line
  two fields more. Upgrade: a product that builds an `Actor::Caller` sets
  both (`"-"` and `None` for a caller not looked up); a log pipeline that
  holds the field set adds them.
- The `[auth.issuer.assurance] claim` path is held to the rule of
  `role_claims` and `resource::PatientClaim` (#234): a path carrying
  whitespace anywhere fails to load (`AssuranceError::Claim`), where only
  a blank step did. Upgrade: name the claim without whitespace.

### Removed

- The flat `[auth] issuer = "…"` form. Upgrade: write an
  `[[auth.issuer]]` table with its `kind`.
- `TokenProfile` and the `token_profile` key, section-level or per issuer.
  Upgrade: select a `profile`, or set `token_types`, `required_claims` and
  `scope_claim` on the issuer; the key fails to load naming them.
- `assurance::ProfessionalSection`, `ClientTokens`, `ActingMode` and
  `Actor`, with the `acting_for_claim` and `client_tokens` keys. Upgrade:
  issue the client a delegated token whose subject is the person, which
  `CallerKind::Delegated` classifies through the issuer's `delegates`; the
  keys fail to load naming it.
- `Caller::acts_for_the_person`. Upgrade: read `Caller::is_the_person` or
  `Caller::kind`.
- `ConfigError::Unqualified`, with the string forms of `scopeless_subjects`
  and `role_claims` it named.

### Fixed

- No `Debug` rendering carries a token claim beyond `sub`, `client_id` and
  `iss` (#229). `resource::Caller` renders the subject, the client, the
  issuer, the kind and the scheme alone, where it rendered every claim, the
  scope, the roles and the `patient` launch context;
  `assurance::Assessment` renders the level alone, and
  `resource::Compartment::Patient` and `resource::PersonContext` leave out
  the patient.

## [0.8.9] - 2026-11-05

### Security

- `[auth] scopeless_subjects` and `role_claims` hold per issuer. An entry
  written `<issuer>#<value>` holds for the tokens of the issuer it names
  alone; a bare entry holds only when the section trusts one issuer. A
  section with several `[[auth.issuer]]` entries refuses a bare entry as
  `ConfigError::Unqualified`, and every section refuses an entry naming an
  issuer it does not trust as `ConfigError::UnknownIssuer`. Before 0.8.9
  both lists applied to the tokens of every trusted issuer: a token from
  any of them whose `sub` was on the allowlist was granted system-wide
  access without a scope (since 0.1.0), and any of them could assert every
  role a product checks, its administrator and emergency roles included
  (since 0.7.0) (CWE-863, CWE-639, GHSA-pfgx-xq28-2629). A deployment with
  several issuers qualifies each entry, or sets `role_claims = []` to read
  no role from a token, before it upgrades: the default `role_claims` is
  bare and refused beside several issuers.

## [0.8.8] - 2026-11-03

### Added

- `client::Reach` names how a connection reaches its server beyond its TLS
  material (#196). It sets the lowest TLS version the connection negotiates
  (`client::TlsVersion`, written `"1.2"` or `"1.3"` in a configuration), and
  the hosts it reaches at a fixed address in place of resolving their names,
  for a server whose name resolves only inside a private network. The URL's
  port and the certificate check against the host name stay as the URL names
  them. `metadata::Http::reaching` builds the engine from a `Tls` and a
  `Reach`; `Http::with_tls` is `reaching` with the default reach, the TLS 1.2
  floor and no override.

## [0.8.7] - 2026-10-31

### Added

- Whether a request is the natural person's own access, for the EHDS
  person-access rights of Regulation (EU) 2025/327 Art. 3, 5 and 9, in two
  answers that fail safe in opposite directions (#171).
  `Caller::acts_for_the_person` is the broad answer, for the Art. 3(3)
  access delay: a bearer token that carries any `patient/` scope of the
  SMART on FHIR or SMART on openEHR grammar, or the deployment's patient
  claim, also beside `user/` or `system/` scopes. `Caller::is_the_person`
  is the strict answer, for Art. 5 authorship and the Art. 9 access record:
  a bearer token with a `patient/` scope and no `user/` or `system/` scope;
  the patient claim alone does not count. A Basic user is neither.
  `Caller::person` returns the `PersonContext` the request is bound to: the
  `patient` launch context, the `ehrId` and the patient claim's value.
- `resource::PatientClaim`, the dotted path of the claim a deployment names
  the patient in, attached to a resource server or introspector with
  `with_extension` so every caller it admits carries it.

## [0.8.6] - 2026-10-27

### Fixed

- `[auth] ca_file` is trusted under `mode = "introspection"` too: the
  metadata, introspection and token calls trust it beside the client or
  bearer grant's own `ca_file`, so an issuer behind a private certificate
  authority is reached with the setting that reaches it in JWT mode (#168).
  A bearer `IntrospectionAuth` now reads the metadata and calls the
  introspection endpoint trusting its grant's trust roots.

## [0.8.5] - 2026-10-27

### Added

- The `openehr-scopes` feature builds `openehr::smart_scopes`, the SMART on
  openEHR scope grammar, which depends on nothing. The crate builds for
  `wasm32-unknown-unknown`, where the grammar is all of it, so a browser
  client parses a scope string with the parser the resource server
  enforces it with (#158, #161).

### Changed

- `openehr::smart_scopes` is this crate's own module, moved from FerroEHR's
  `openehr-sdt` with the same path, types and behaviour, and the crate no
  longer depends on `openehr-sdt` (#158). A `0.0.x` requirement on that
  crate was exact, so each FerroEHR release left this crate behind and a
  product resolved two copies. A product that passes
  `openehr_sdt::smart_scopes` types to this crate names
  `ferrohealth_smart::openehr::smart_scopes` instead; cargo-semver-checks
  finds no other change to the public API.

## [0.8.4] - 2026-10-27

### Changed

- Requires `openehr-sdt` 0.0.109, the version FerroEHR publishes, so a
  product that also takes FerroEHR's openEHR crates resolves one
  `openehr-sdt` (#154). The `openehr` feature's re-exported scope types
  come from that version.

## [0.8.3] - 2026-10-27

### Changed

- `openehr-sdt` 0.0.102 in place of 0.0.98, the newest version on
  crates.io. The `openehr::smart_scopes` re-export names the 0.0.102 types,
  so a product with the `openehr` feature that depends on `openehr-sdt`
  itself moves to 0.0.102 with it (#148).

## [0.8.2] - 2026-10-27

### Fixed

- A misspelt key inside an `[[auth.issuer]]` entry is refused by its name.
  `config::IssuerKey` read the flat and list forms as an untagged enum,
  whose refusal ("data did not match any variant") dropped the entry's own
  error; it is now read by the value's shape, so the entry's
  `deny_unknown_fields` refusal reaches the operator (#145).

## [0.8.1] - 2026-10-27

### Fixed

- The documentation builds without a broken link under the default
  features and with no features, where it linked to the modules behind
  `openehr`, `axum` and `fetch` (#135). docs.rs builds every feature.

## [0.8.0] - 2026-10-26

### Added

- The `oidc` feature: `oidc::RelyingParty`, the OpenID Connect
  relying-party client every operator console signs in with (#131). It
  builds the authorization request with `state`, `nonce` and a PKCE `S256`
  challenge (OpenID Connect Core 1.0 §3.1.2.1, RFC 7636 §4), refuses a
  callback whose `state` is not the sign-in's before reading anything else
  (RFC 6749 §10.12), exchanges the code with the verifier, checks the ID
  Token's signature, `iss`, `aud`, `azp`, `exp` and `nonce` (OpenID Connect
  Core 1.0 §3.1.3.7), refreshes the access token (RFC 6749 §6), revokes a
  token (RFC 7009 §2.1), and returns the end-session URL (OpenID Connect
  RP-Initiated Logout 1.0 §2). Every failure is a typed `oidc::OidcError`
  carrying the provider's status and error code. Tokens are held in
  `ferrohealth_secret::secret::Secret` and none is rendered; the console
  keeps the session.
- `metadata::ServerMetadata::end_session_endpoint` (OpenID Connect
  RP-Initiated Logout 1.0 §2.1).

## [0.7.5] - 2026-10-26

### Changed

- It requires `ferrohealth-secret` 0.2 as a caret requirement (`0.2.0`), so a
  secret patch reaches a product without a smart release first.

## [0.7.4] - 2026-10-26

### Changed

- It builds on `ferrohealth-secret` 0.2.0, so a product can take the newest
  family mask beside it.
- `[auth.basic] cache_ttl_seconds` defaults to 300: a credential that verified
  is kept for five minutes, so a repeat request skips the Argon2id key
  derivation (#127). Each request otherwise costs about 10 ms of CPU, which
  capped a product's throughput. `cache_ttl_seconds = 0` keeps the old
  behaviour.

## [0.7.3] - 2026-10-26

### Changed

- Every secret and every masked URL renders through `ferrohealth-secret`,
  the family's one mask: `config::REDACTED` is its `***` in place of
  `[redacted]`, and `config::mask_userinfo` renders a URL through its
  `RedactedUrl`, so the query is masked as `?***` beside the userinfo. The
  `OauthSection` and `AuthSection` renderings follow. Text without `://` is
  still kept as written.

## [0.7.2] - 2026-10-26

### Added

- `[auth] ca_file`: a PEM file of trust roots added to the platform's for
  every issuer's discovery document and key set, so an issuer behind a
  private certificate authority can be reached without changing the trust
  of the whole process. `resource::Settings::trust_roots` carries it to
  `ResourceServer::discover`. A file that cannot be read, is no PEM or holds
  no certificate refuses the start as `ConfigError::CaFile`.

## [0.7.1] - 2026-10-26

### Added

- `config::mask_userinfo` and `config::REDACTED` are public, so a product
  renders every URL of its configuration with the one mask the shared
  sections use.

### Changed

- A masked URL keeps the rest of the URL as written: `[redacted]` stands in
  for the userinfo in place of a percent-encoded `%5Bredacted%5D`, and an
  explicit default port is no longer dropped.

- The changelog moves from the repository root to
  `crates/ferrohealth-smart/CHANGELOG.md`, beside `ferrohealth-authz`'s, and
  the published crate carries it.

### Security

Shipped with functional changes because: the fix is the public mask the Added entry names, so the two cannot ship apart.

- Every rendering of `OauthSection` masks the userinfo of its `issuer` and
  `token_endpoint`, a URL no parser accepts included. Before 0.7.1 a
  credential in those URLs could reach the rendering in full: through
  `Debug` since 0.1.0 and `Serialize` since 0.3.0, and in 0.7.0 still
  whenever the URL did not parse. A product that logged its configuration
  could write the credential to its log (CWE-532, GHSA-vphj-3f8c-5hpx).

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

[Unreleased]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.9.0...HEAD
[0.9.0]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.8.9...ferrohealth-smart-v0.9.0
[0.8.9]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.8.8...ferrohealth-smart-v0.8.9
[0.8.8]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.8.7...ferrohealth-smart-v0.8.8
[0.8.7]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.8.6...ferrohealth-smart-v0.8.7
[0.8.6]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.8.5...ferrohealth-smart-v0.8.6
[0.8.5]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.8.4...ferrohealth-smart-v0.8.5
[0.8.4]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.8.3...ferrohealth-smart-v0.8.4
[0.8.3]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.8.2...ferrohealth-smart-v0.8.3
[0.8.2]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.8.1...ferrohealth-smart-v0.8.2
[0.8.1]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.8.0...ferrohealth-smart-v0.8.1
[0.8.0]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.7.5...ferrohealth-smart-v0.8.0
[0.7.5]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.7.4...ferrohealth-smart-v0.7.5
[0.7.4]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.7.3...ferrohealth-smart-v0.7.4
[0.7.3]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.7.2...ferrohealth-smart-v0.7.3
[0.7.2]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.7.1...ferrohealth-smart-v0.7.2
[0.7.1]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-smart-v0.7.0...ferrohealth-smart-v0.7.1
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
