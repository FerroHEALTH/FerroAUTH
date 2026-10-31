<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

## What changed and why

<!-- Describe the change and the reason for it. Name what a product must change if an API breaks. -->

Closes #NNN

## Checklist

- [ ] Every conformance decision cites the specification (SMART App Launch, the OAuth 2.0, JWT and Basic RFCs, OpenID Connect Discovery), never memory and never another implementation.
- [ ] Rust gates pass: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` with and without `--all-features`, `cargo nextest run --workspace --locked` with and without `--all-features`, `cargo doc` with `RUSTDOCFLAGS=-D warnings`, and `cargo deny check`.
- [ ] Every refusal the change adds has an asserted negative test, and no test was weakened to pass.
- [ ] Shell and workflow files are clean: `shellcheck --severity=style`, `actionlint`, `zizmor --min-severity=low .github/`.
- [ ] The changed crate's `crates/<crate>/CHANGELOG.md` has an `[Unreleased]` entry, if a product sees the change.
- [ ] No key, token, password, secret or patient data in a fixture, test or example; every key a test uses is generated when it runs.
- [ ] Every commit is signed.
- [ ] No AI or assistant attribution anywhere in the commits or this PR.
