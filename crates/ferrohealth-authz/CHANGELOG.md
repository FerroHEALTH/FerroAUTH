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

[Unreleased]: https://github.com/FerroHEALTH/FerroAUTH/commits/main/crates/ferrohealth-authz
