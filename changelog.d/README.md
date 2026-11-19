<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog fragments

A pull request with a user-visible effect adds one file here instead of
editing a changelog, so two pull requests never touch the same lines. Each of
the four changelogs has its own directory:

| Directory | Changelog | Released by the tag |
|---|---|---|
| `changelog.d/ferrosmart/` | `app/ferrosmart/CHANGELOG.md` | `ferrosmart-vX.Y.Z` |
| `changelog.d/ferrohealth-smart/` | `crates/ferrohealth-smart/CHANGELOG.md` | `ferrohealth-smart-vX.Y.Z` |
| `changelog.d/ferrohealth-authz/` | `crates/ferrohealth-authz/CHANGELOG.md` | `ferrohealth-authz-vX.Y.Z` |
| `changelog.d/ferrohealth-session/` | `crates/ferrohealth-session/CHANGELOG.md` | `ferrohealth-session-vX.Y.Z` |

The directories sit here, at the repository root, and not inside the crates:
a file under `crates/<crate>/` is packaged content, so a fragment there would
change what `cargo package` uploads and ask for a version bump of its own.

- **Name:** `changelog.d/<package>/<issue>-<kebab-slug>.<section>.md`, for
  example `changelog.d/ferrosmart/696-changelog-fragments.changed.md`.
  `<section>` is a Keep a Changelog 1.1.0 section in lower case: `added`,
  `changed`, `deprecated`, `removed`, `fixed` or `security`.
- **Content:** the entry exactly as it reads in the changelog, one or more
  list items that open with `- ` and continue on lines indented by two
  spaces, with no heading and no blank line inside. A fragment carries no
  SPDX header: its text moves into the changelog, which carries the header.
- **Issue reference:** the cut ends the first paragraph of each entry with
  `(#<issue>)`, the number the file name starts with, unless the entry
  already names that issue.
- **A change to two packages** adds one fragment to each directory.

## Security entries

A `security` fragment names its advisory itself: the `GHSA-xxxx-xxxx-xxxx` id
of the security advisory drafted for the fix, or the path of the OpenVEX
statement under `security/vex/` that judges it, which must exist
(`docs/release.md`, Security entries).

When a package's release carries `security` fragments beside any other
section, its `### Security` section opens with a reason line (Regulation (EU)
2024/2847 Annex I Part II(2)). That line is a fragment of its own:

- **Name:** `<issue>-<kebab-slug>.security-reason.md`, at most one per
  package.
- **Content:** one paragraph that opens with `Shipped with functional changes
  because: ` and the reason, with no list item and no blank line inside. It
  is copied as written, with no issue reference added.

The cut places it first under `### Security`.

## Checks

- `scripts/release/changelog.sh --check` validates every fragment's place,
  name and form.
- `scripts/release/changelog.sh --preview <package>` prints the changelog
  with the package's fragments folded into `[Unreleased]`, as the next cut
  would write it.
- `scripts/release/changelog.sh --check-preview` runs
  `scripts/checks/changelog-structure.sh` and
  `scripts/checks/changelog-security.sh` over every package's preview, so a
  Security entry without its advisory, or a missing reason, fails the pull
  request that adds it.
- `scripts/checks/changelog-guard.sh <base> <head>` asks for a fragment when
  the change touches `app/`, `crates/`, `docker/`, a compose file or the root
  `Cargo.toml` and `Cargo.lock`, and refuses a change that writes under
  `[Unreleased]` or a pending `## [X.Y.Z] - Unreleased` section of any
  changelog. The `no-changelog` label waives the fragment for a change with
  no user-visible effect, never the refusal.
- `scripts/checks/release-window.sh` refuses a fragment of a package whose
  newest dated section is not tagged yet.

CI runs every one of them in the `guards` job.

## The cut

On the release branch,
`scripts/release/changelog.sh --assemble <package> <version> <date>` writes
the package's dated section from its fragments (and from a pending section a
breaking change opened), moves the link references on and deletes the
fragments; you then write the release summary under the heading
(`docs/release.md`). The release `plan` job refuses a tag whose package still
holds a fragment. This README is not a fragment.
