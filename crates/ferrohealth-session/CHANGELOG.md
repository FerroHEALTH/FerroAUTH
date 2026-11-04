<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog of ferrohealth-session

All notable changes to `ferrohealth-session` are documented in this file. It
keeps its own version line, released by the tag
`ferrohealth-session-vX.Y.Z`; `ferrohealth-smart` and `ferrohealth-authz`
keep their own.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2026-11-04

### Added

- `clock::Clock` is public, the time every lifetime is counted on, and
  `sessions::Sessions::with_clock` builds a store on one; `Sessions::new`
  stays on the wall clock (#206).
- `clock::ManualClock`, behind the new `test-clock` feature, is a time a
  console's tests set and move (`new`, `clock`, `now`, `set`, `advance`), so
  a session test reaches an idle or absolute timeout without waiting for the
  wall clock (#206).

## [0.2.1] - 2026-11-03

### Fixed

- `POST /logout` sends the operator to the provider's end-session endpoint
  only when the ended session holds an ID Token (OpenID Connect RP-Initiated
  Logout 1.0 §2), and otherwise redirects to `Pages::signed_out` (#201).
  A Basic sign-out on a console that also has a provider configured went to
  the provider, which held no session of the operator's to end. Revocation
  is unchanged.

## [0.2.0] - 2026-11-03

### Added

- `[oidc] resolve` reaches provider hosts at a fixed address in place of
  resolving their names, for a provider whose name resolves only inside a
  private network (#196). Each entry is `host=ip:port`, and an entry that is
  not refuses the section with the new `ConfigError::Resolve`. The URL's port
  and the certificate check against the host name stay as the URL names them.
  The override reaches the provider client only.
- `[oidc.tls]`: the client certificate the console presents to its provider
  (RFC 8705 §2), as `client_certificate` with `client_key` or
  `client_key_file`, and `min_version`, the lowest TLS version of the
  provider connection (`"1.2"`, the default, or `"1.3"`). A certificate
  without its key, or a key without its certificate, is refused with
  `ConfigError::ClientIdentityHalf`, and a certificate file that cannot be
  read with `ConfigError::ClientCertificate`. The key is read as a secret.

### Changed

- `config::OidcSection` carries the two new fields `resolve` and `tls`
  (`config::OidcTlsSection`). A console that builds the section with a struct
  literal naming every field adds them, or ends the literal with
  `..OidcSection::default()`. `ferrohealth-session` requires
  `ferrohealth-smart` 0.8.8, whose `client::Reach` the provider client is
  built with.

## [0.1.1] - 2026-11-03

### Added

- `config::OidcSection::check` refuses a section a console cannot sign in
  with safely: the issuer or a written endpoint that is not `https` off a
  loopback host (RFC 6749 §3.1), a `redirect_uri` that is no `http` or
  `https` URL with a host and no userinfo or that carries a fragment
  (RFC 6749 §3.1.2), `scopes` without `openid` (OpenID Connect Core 1.0
  §3.1.2.1), and `scopes` that list `offline_access`, which
  `offline_access = true` asks for (§11). The refusals are the new
  `ConfigError::UrlShape`, `NoOpenId` and `OfflineAccessScope` (#181).
- The session watch answers a gone session with an RFC 9457 problem
  (`application/problem+json`, `about:blank`, status `401`) whose `detail`
  the console words through the new `routes::Pages::session_gone`, which
  has an English default (#183).
- `sessions::Sessions::session_preference` writes a preference cookie with
  no `Max-Age`, which the browser keeps until its session ends
  (RFC 6265 §4.1.2.2), beside `preference` and its `Max-Age` (#184).

### Fixed

- `return_path::ReturnPath::parse` refuses every page under the sign-in
  page, such as `/sign-in/expired`, as well as the sign-in page itself, so a
  completed sign-in never lands on the page that says the session ended
  (#180).

## [0.1.0] - 2026-11-03

The first release: the OpenID Connect sign-in and the session of the
FerroHEALTH operator consoles, over the relying party of `ferrohealth-smart`
0.8. Consoles pin `=0.1.0` with the `axum` feature.

### Added

- The sign-in and the session of the FerroHEALTH operator consoles, one
  crate in place of the copy each console carried (#177). `config` reads the
  `[oidc]` and `[session]` sections with `deny_unknown_fields` and every
  secret through `ferrohealth-secret`; with `issuer` alone the endpoints are
  discovered. `sessions::Sessions` keeps the pending sign-ins and the
  sessions in a `memory` store (bounded pools, an opaque id in the cookie)
  or a `sealed` one (one AES-256-GCM cookie that every instance holding the
  key opens). A sealed store without a key, or with `offline_access`, is
  refused when the configuration loads.
- The idle and the absolute lifetime, counted from times the session
  carries, the absolute one from the sign-in time; an access token no
  refresh token can replace ends the session when it expires. `Sessions::left`
  answers FerroUI's session-watch wire (`{"idle": s, "absolute": s}`): a read
  never counts as activity, an extension starts the idle lifetime again.
- `Sessions::keep_fresh` renews an access token before it expires through
  `ferrohealth-smart`'s relying party, one refresh per session at a time; a
  refusal ends the session, and a provider that cannot be reached is a
  `refresh::Freshness::Unreached`, never a silent success.
- `routes` (feature `axum`): `GET /login` with a `?return=` path held to the
  console's own pages, `GET /auth/callback`, `POST /logout` with RFC 7009
  revocation and RP-initiated logout, and `GET`/`POST /session`, the same
  four routes on every console, with the middleware that hands every page
  its request's `record::Held` and the `routes::Pages` trait a console draws
  a stopped sign-in through.

[Unreleased]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-session-v0.2.2...HEAD
[0.2.2]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-session-v0.2.1...ferrohealth-session-v0.2.2
[0.2.1]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-session-v0.2.0...ferrohealth-session-v0.2.1
[0.2.0]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-session-v0.1.1...ferrohealth-session-v0.2.0
[0.1.1]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-session-v0.1.0...ferrohealth-session-v0.1.1
[0.1.0]: https://github.com/FerroHEALTH/FerroAUTH/releases/tag/ferrohealth-session-v0.1.0
