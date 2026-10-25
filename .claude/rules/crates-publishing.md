<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Published crate discipline (crates.io)

Two crates are published on crates.io so the FerroHEALTH products can
depend on them: `crates/ferrohealth-smart` as `ferrohealth-smart` and
`crates/ferrohealth-authz` as `ferrohealth-authz`. Both are BUSL-1.1.
Published versions are immutable, so version hygiene is a hard rule.

## Two version lines

The workspace `version` in the root `Cargo.toml` is `ferrohealth-smart`'s
version and its release tag `vX.Y.Z`; it inherits it (`version.workspace =
true`), and its changelog is `CHANGELOG.md`. `ferrohealth-authz` keeps its own
`[package] version`, released by the tag `ferrohealth-authz-vX.Y.Z`, with its
own `crates/ferrohealth-authz/CHANGELOG.md`. For each, the tag, the crate and
the changelog section always agree (`scripts/checks/crate-version-guard.sh`,
`scripts/release/plan.sh`).

## The bump rule

- **A release bumps the crate's version, its changelog section and the lock
  together** (`cargo update -w`), in the release pull request. A
  `ferrohealth-smart` release that `ferrohealth-authz` must follow also moves
  the `ferrohealth-smart` requirement of `[workspace.dependencies]`.
- Consumers pin the crate exactly (`ferrohealth-smart = "=0.1.0"`): Cargo
  reads a `0.x` caret requirement as compatible across patches
  (<https://doc.rust-lang.org/cargo/reference/semver.html>), and a product
  moves its pin deliberately, in lockstep with the other products.
- A pull request that breaks a public API says so in its body and its
  CHANGELOG entry, naming what a product changes; while the line is `0.x`,
  such a release moves the minor version.

## The publish lane is resumable and verified

`scripts/release/publish-crates.sh` (`publish <crate>` / `verify <crate>` /
`version` / `crate <tag>` / `guard`) uploads the one crate a tag releases,
counts "already exists" as done, and reads the registry back before reporting
success. Two lanes call it: the `crates` leg of `release.yml` on a `v*` or
`ferrohealth-authz-v*` tag (the primary path, paused by the `crates-io`
environment's required reviewer) and `publish-crates.yml` on a manual
dispatch (a dry run by default; `publish = true` is the recovery path for
an existing release, refused by its `guard` job unless the run is at the
release tag of a crate at its manifest version and that tag has a published
GitHub release). Both
authenticate with crates.io Trusted Publishing (OIDC through
`rust-lang/crates-io-auth-action`); no long-lived crates.io token exists in
the repository. Neither lane restores a build cache (`ci-cd.md`).

`cargo publish --workspace --dry-run --locked` runs on every pull request as
the `publish-dry-run` job; Cargo packages the members together, so
`ferrohealth-authz` verifies against the `ferrohealth-smart` beside it before
that version is on crates.io.

## Owner steps (done once)

1. The name was reserved at `0.0.0` by the owner's crates.io login on
   2026-10-19, since a first version cannot use Trusted Publishing.
2. On crates.io, the crate's Trusted Publishing carries two GitHub entries:
   repository owner `FerroHEALTH`, repository `FerroAUTH`, workflows
   `release.yml` and `publish-crates.yml`, environment `crates-io`.
   `ferrohealth-authz`, the policy decision crate reserved at `0.0.0`, has
   Trusted Publishing for the same repository.
3. The `crates-io` GitHub environment carries the owner as required reviewer
   and admits `main`, `v*` tags and `ferrohealth-authz-v*` tags.

## Official documentation (durable citations)

- Trusted Publishing on crates.io: <https://crates.io/docs/trusted-publishing>
- `cargo publish`: <https://doc.rust-lang.org/cargo/commands/cargo-publish.html>
