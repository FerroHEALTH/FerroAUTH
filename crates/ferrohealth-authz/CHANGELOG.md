<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog of ferrohealth-authz

All notable changes to `ferrohealth-authz` are documented in this file. It
keeps its own version line, released by the tag
`ferrohealth-authz-vX.Y.Z`; `ferrohealth-smart` keeps its changelog in the
repository root.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- docs.rs builds every feature, so the `cedar` and `remote` modules are
  documented there (#135).

## [0.2.0] - 2026-10-26

### Changed

- Takes `ferrohealth-smart` 0.8.0, the line it releases beside.
  `request::Subject::of` takes a `ferrohealth_smart::resource::Caller` and
  `remote::RemotePdp::new` a `ferrohealth_smart::client::cache::TokenSource`,
  so a product moves both crates together; nothing else it calls changes.

## [0.1.5] - 2026-10-26

### Changed

- Takes `ferrohealth-smart` 0.7.5, the line it releases beside.

## [0.1.4] - 2026-10-26

### Changed

- Takes `ferrohealth-smart` 0.7.4, the line it releases beside.

## [0.1.3] - 2026-10-26

### Changed

- Takes `ferrohealth-smart` 0.7.3, the line it releases beside.

## [0.1.2] - 2026-10-26

### Changed

- Takes `ferrohealth-smart` 0.7.2, the line it releases beside.

## [0.1.1] - 2026-10-26

### Changed

- Takes `ferrohealth-smart` 0.7.1, the line it releases beside.

## [0.1.0] - 2026-10-25

The first release: the policy decision of the FerroHEALTH products, the
NIST SP 800-162 request over the subject `ferrohealth-smart` 0.7.0
authenticates, with the Cedar engine behind `cedar` and the remote decision
point behind `remote`. Products pin `=0.1.0` beside `ferrohealth-smart`
`=0.7.0`.

### Added

- The policy decision of the FerroHEALTH products, moved out of FerroEHR and
  generalised so every product can use it (#103). `request::Subject` is read
  from the caller `ferrohealth-smart` admitted (its subject id, roles, scopes
  and chosen claims); `request::Request` names an action, a resource type,
  resource attributes (a set fans out, every combination must be permitted)
  and context attributes; `request::Decision` carries the policies that made
  it. `engine::PolicyEngine` is the trait every engine implements, and
  `engine::AuthzError` the answer of one that cannot decide, which a product
  never reads as a permit.
- `cedar` (feature `cedar`): the embedded engine over the Cedar policy
  language. The schema is written from the product's `cedar::Model`, the
  operator's policies are validated strictly at load and at every reload, a
  reload that does not validate keeps the set in force, and a policy that
  errors during evaluation makes the evaluation an error instead of being
  skipped.
- `remote` (feature `remote`): a remote policy decision point over HTTP, one
  call per combination with the bound attributes as a flat JSON object,
  `200` a permit, a `4xx` a deny and every other answer no decision,
  authorized with the client credentials token of `ferrohealth-smart`.

[Unreleased]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-authz-v0.2.0...HEAD
[0.2.0]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-authz-v0.1.5...ferrohealth-authz-v0.2.0
[0.1.5]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-authz-v0.1.4...ferrohealth-authz-v0.1.5
[0.1.4]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-authz-v0.1.3...ferrohealth-authz-v0.1.4
[0.1.3]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-authz-v0.1.2...ferrohealth-authz-v0.1.3
[0.1.2]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-authz-v0.1.1...ferrohealth-authz-v0.1.2
[0.1.1]: https://github.com/FerroHEALTH/FerroAUTH/compare/ferrohealth-authz-v0.1.0...ferrohealth-authz-v0.1.1
[0.1.0]: https://github.com/FerroHEALTH/FerroAUTH/releases/tag/ferrohealth-authz-v0.1.0
