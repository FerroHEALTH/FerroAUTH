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

[Unreleased]: https://github.com/FerroHEALTH/FerroAUTH/commits/main/crates/ferrohealth-session
