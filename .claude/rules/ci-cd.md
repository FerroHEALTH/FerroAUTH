---
paths:
  - ".github/**"
  - "scripts/**"
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# CI/CD and supply-chain discipline

No specification governs this: our own design, grounded in the OWASP GitHub
Actions Security Cheat Sheet, SLSA v1.0, OpenSSF Scorecard, and Sigstore.

## What runs

- `.github/workflows/ci.yml`: the gate on every pull request, merge-group run
  and push to `main`. The workflow tier (zizmor, actionlint, shellcheck, the
  comment-style guard, the `TODO(#N)` guard, the contribution-licence
  guard) and the Rust tier (`cargo fmt --all --check`; `cargo clippy
  --workspace --all-targets --locked -- -D warnings` with and without
  `--all-features`; `cargo nextest run --workspace --locked` with and without
  `--all-features`, plus `cargo test --doc`; `cargo doc` with
  `RUSTDOCFLAGS=-D warnings`; `cargo deny check`; `cargo publish -p
  ferrohealth-smart --dry-run --locked`; the crate-version guard and
  `dependency-review-action` on pull requests). The `conclusion` job is the
  single required status check on `main`.
- `.github/workflows/pr-guards.yml`: `ci.yml` runs on `opened`, `synchronize`
  and `reopened` only, so a commit gets one run; when the description
  changes, this waits for the CI run on the head commit to complete and
  re-runs `contribution-licence`, which re-runs `conclusion` with it.
- `.github/workflows/specs.yml`: the vendored-specification guard,
  `scripts/checks/versions.sh`, offline, on the same events.
- `.github/workflows/codeql.yml`: CodeQL over the `actions` language and Rust.
- `.github/workflows/scorecard.yml`: OpenSSF Scorecard, published to the
  OpenSSF API and to code scanning.
- `.github/workflows/release.yml`: dormant until a `v*` tag is pushed. It
  validates the tag against the workspace version, takes the notes from the
  matching section of the tagged crate's `crates/<crate>/CHANGELOG.md`, creates the release as a draft, calls
  `release-crate.yml` (a reusable workflow, so the signing identity stays out
  of reach of caller steps) to package the `.crate`, attest it and attach it,
  publishes the release, and then its `crates` leg uploads the crate through
  Trusted Publishing behind the `crates-io` environment
  (`crates-publishing.md`).
  Its `plan` job refuses a tag when no milestone is titled exactly as the tag
  or that milestone still holds an open issue or pull request, naming each
  one, and its last job, `milestone`, closes that milestone once every leg,
  crates included, has succeeded; a failed leg leaves it open and the job log
  names the leg. Both call `scripts/release/milestone.sh`.
- `.github/workflows/publish-crates.yml`: the manual crates.io lane, a dry
  run unless `publish` is set, sharing `scripts/release/publish-crates.sh`
  with the release lane. A real publish runs only at the tag of the
  manifest version that has a published GitHub release: its `guard` job
  refuses any other ref before the approval (`docs/release.md`).

## Workflow security (every workflow, no exceptions)

- **Every `uses:` is pinned to a full commit SHA** with a trailing `# vX.Y.Z`
  comment; Dependabot (`github-actions`) bumps them.
- **`permissions: {}` at workflow level**, with the minimum granted per job.
- **`persist-credentials: false`** on every `actions/checkout`.
- **No `${{ }}` context interpolation inside `run:`:** pass context through
  `env:`.
- **A publishing lane restores no build cache.**

Run `zizmor --min-severity=low .github/`, `actionlint` and `shellcheck
--severity=style` by hand before pushing a workflow or script change. A
finding is fixed, or carries a `# zizmor: ignore[audit]` or `# shellcheck
disable=SCnnnn` with its reason on the line it names; no `.shellcheckrc`
exists.

## Supply chain

- **A release is assembled as a draft and published last.** The fix for a bad
  cut is a new patch version, never a retag: immutable releases freeze a
  published release, and the `release-tags` ruleset stops a tag being moved
  or deleted.
- **Every tag is signed**, on the merge commit on `main`.
- **Always `--locked`**, and `Cargo.lock` is committed.
- **The crate publishes through Trusted Publishing** (OIDC, no long-lived
  token), with a dry run on every pull request.

## Never

- Never unpin a `uses:`, widen a job's permissions without cause, interpolate
  context into `run:`, or restore a cache in a publishing lane.
- Never weaken a gate to go green (`testing.md`); fix the cause.
- **Never add AI or Claude attribution** to any commit, PR, or release text.

## Official documentation (durable citations)

- OWASP GitHub Actions Security Cheat Sheet:
  <https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html>
- SLSA v1.0: <https://slsa.dev/spec/v1.0/>
- OpenSSF Scorecard: <https://github.com/ossf/scorecard-action>
- Trusted Publishing on crates.io: <https://crates.io/docs/trusted-publishing>
