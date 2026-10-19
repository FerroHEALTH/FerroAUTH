<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Published crate discipline (crates.io)

`crates/ferrohealth-smart` is published on crates.io as `ferrohealth-smart`
so the FerroHEALTH products can depend on it. The crate is BUSL-1.1.
Published versions are immutable, so version hygiene is a hard rule.

## One version line

The workspace `version` in the root `Cargo.toml` is the library's version and
the release tag `vX.Y.Z`. The library inherits it (`version.workspace =
true`), so the tag, the crate and the changelog section always agree.

## The bump rule

- **A release bumps the workspace version, the changelog section and the
  lock together** (`cargo update -w`), in the release pull request.
- Consumers pin the crate exactly (`ferrohealth-smart = "=0.1.0"`): Cargo
  reads a `0.x` caret requirement as compatible across patches
  (<https://doc.rust-lang.org/cargo/reference/semver.html>), and a product
  moves its pin deliberately, in lockstep with the other products.
- A pull request that breaks a public API says so in its body and its
  CHANGELOG entry, naming what a product changes; while the line is `0.x`,
  such a release moves the minor version.

## The publish lane is resumable and verified

`scripts/release/publish-crates.sh` (`publish` / `verify` / `version`)
uploads the crate, counts "already exists" as done, and reads the registry
back before reporting success. Two lanes call it: the `crates` leg of
`release.yml` on a `v*` tag (the primary path, paused by the `crates-io`
environment's required reviewer) and `publish-crates.yml` on a manual
dispatch (a dry run by default; `publish = true` is the recovery path). Both
authenticate with crates.io Trusted Publishing (OIDC through
`rust-lang/crates-io-auth-action`); no long-lived crates.io token exists in
the repository. Neither lane restores a build cache (`ci-cd.md`).

`cargo publish -p ferrohealth-smart --dry-run --locked` runs on every pull
request as the `publish-dry-run` job.

## Owner steps (done once)

1. The name was reserved at `0.0.0` by the owner's crates.io login on
   2026-10-19, since a first version cannot use Trusted Publishing.
2. On crates.io, the crate's Trusted Publishing carries two GitHub entries:
   repository owner `FerroHEALTH`, repository `FerroSMART`, workflows
   `release.yml` and `publish-crates.yml`, environment `crates-io`.
3. The `crates-io` GitHub environment carries the owner as required reviewer
   and admits `main` and `v*` tags.

## Official documentation (durable citations)

- Trusted Publishing on crates.io: <https://crates.io/docs/trusted-publishing>
- `cargo publish`: <https://doc.rust-lang.org/cargo/commands/cargo-publish.html>
