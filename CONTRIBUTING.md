<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Contributing to FerroAUTH

FerroAUTH holds two crates of the FerroHEALTH products: authentication,
`ferrohealth-smart`, the shared SMART App Launch and OAuth 2.0
resource-server crate, and the policy decision, `ferrohealth-authz`. The
working discipline is [`CLAUDE.md`](CLAUDE.md) and the design of record is
[`docs/architecture.md`](docs/architecture.md). Read both before making a
change. The contribution terms every FerroHEALTH product shares are in the
family book at <https://ferrohealth.eu/docs/licensing.html#contributions>.

## Build and test

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --workspace --locked
cargo nextest run --workspace --all-features --locked
cargo test --doc --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps --document-private-items
cargo deny check
```

Every upstream in the tests is a `wiremock` stub and every signing key is
generated when the case runs; no test reaches the network, and no key,
token, secret or password is committed.

A change to a workflow or a shell script also needs the linters CI runs:

```
zizmor --min-severity=low .github/
actionlint
shellcheck --severity=style <the shell files you touched>
```

A change to a vendored specification goes through its `scripts/vendor/*.sh`
fetcher and `docs/VERSIONS.md`; `scripts/checks/versions.sh` holds the tree
to its provenance.

## The specifications are the authority

SMART App Launch 2.2.0, the OAuth 2.0 and JOSE RFCs and OpenID Connect
Discovery 1.0, as vendored under `docs/specs/`, decide every check,
challenge, claim rule and grant; the docs.rs pages of the pinned crates
decide how the tools are used. Cite the section in the pull request and in
each `// NOTE:`. Where none governs a choice, say so: "no specification
governs this: our own design".

## Branches and commits

- Branch names use conventional types: `feat/<slug>`, `fix/<slug>`,
  `chore/<slug>`, `docs/<slug>`, `refactor/<slug>`, `perf/<slug>`,
  `test/<slug>`, `ci/<slug>`, `build/<slug>`, `release/<slug>`.
- Commit messages describe only the change. Do **not** add AI or assistant
  attribution, co-author trailers, or "generated with" lines anywhere.
- **Sign your commits.** `main` refuses an unsigned commit.

## Pull requests

- Declare `Closes #N`, one keyword per issue.
- Never weaken, skip, or delete a test to make a build pass; every refusal
  you add has an asserted negative test.
- Add a `CHANGELOG.md` entry under `[Unreleased]` for any change a product
  sees, and name what a product must change when an API breaks.
- Write prose to `.claude/rules/writing-style.md`.

## Using AI tools

You may. If a contribution has AI-generated content, say so in the pull
request description: which tool, and what it did. Disclosure lives in the
description, never in a commit trailer. You remain responsible for the
submission in full.

## Security

Report vulnerabilities privately; see [`SECURITY.md`](SECURITY.md). Do not
open a public issue for a security problem.

## Licensing of contributions

FerroAUTH's own code is licensed under the Business Source License 1.1
([`LICENSE`](LICENSE)). These are the terms the family book states for every
FerroHEALTH product
([Contributions](https://ferrohealth.eu/docs/licensing.html#contributions)).
By submitting a contribution you:

1. certify that you wrote it, or otherwise have the right to submit it under
   these terms;
2. license it under the Business Source License 1.1 as applied to the version
   it lands in, including that version's Change License, so it becomes Apache
   2.0 with the rest of that version; and
3. grant the Licensor named in `LICENSE`, Cadasto B.V., a perpetual,
   irrevocable, worldwide, royalty-free, transferable right to use, reproduce,
   modify, distribute, sublicense and relicense the contribution as part of
   the Licensed Work under any terms, including commercial licences.

You keep your copyright. There is no separate agreement to sign: the pull
request template carries a checkbox recording your acceptance of these terms,
and a pull request from a person does not merge without it (the
`contribution-licence` check, backed by
`scripts/checks/contribution-licence.sh`).
