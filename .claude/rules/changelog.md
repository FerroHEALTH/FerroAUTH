---
paths:
  - "changelog.d/**"
  - "**/CHANGELOG.md"
  - "scripts/release/**"
  - "scripts/checks/changelog-*.sh"
  - "scripts/checks/release-window.sh"
---

# The changelogs and their fragments

Four changelogs follow Keep a Changelog 1.1.0, one per release line:
`app/ferrosmart/CHANGELOG.md`, `crates/ferrohealth-smart/CHANGELOG.md`,
`crates/ferrohealth-authz/CHANGELOG.md` and
`crates/ferrohealth-session/CHANGELOG.md`. A release's notes are its
section, so what the section says is what users read. The cut itself is
`docs/release.md`.

## Fragments

No specification governs the fragments: our own design, the one the
FerroHEALTH products share, so two open pull requests never touch the same
lines of a changelog.

- **One file per change and package:**
  `changelog.d/<package>/<issue>-<kebab-slug>.<section>.md`, where
  `<package>` is `ferrosmart`, `ferrohealth-smart`, `ferrohealth-authz` or
  `ferrohealth-session`, and `<section>` is `added`, `changed`,
  `deprecated`, `removed`, `fixed` or `security`. Its content is the entry as
  it reads in the changelog: one or more list items that open with `- `,
  continued on lines indented by two spaces, with no heading, no blank line
  inside and no SPDX header. The cut ends each entry with `(#<issue>)`
  unless it already names that issue. `changelog.d/README.md` is the format
  note.
- **Never edit `[Unreleased]` or a pending `## [X.Y.Z] - Unreleased`
  section.** The one changelog edit a pull request makes is the release cut,
  or the empty pending heading the first breaking change after a release
  opens (`docs/release.md`, When the version moves).
- **The reason line is a fragment of its own:**
  `<issue>-<kebab-slug>.security-reason.md`, at most one per package, one
  paragraph opening `Shipped with functional changes because: `. The cut
  puts it first under `### Security`.
- **CI checks both halves** in the `guards` job:
  `scripts/release/changelog.sh --check` (every fragment's place, name and
  form), `--check-preview` (the structure and Security checks over each
  changelog with its fragments folded in), and on a pull request
  `scripts/checks/changelog-guard.sh`: a change to `app/`, `crates/`,
  `docker/`, a compose file or the root Cargo manifest and lock adds a
  fragment, and a change that writes under `[Unreleased]` or a pending
  section is refused. The `no-changelog` label waives the fragment for a
  change with no effect a product sees, never the refusal; the step reads
  the label when it runs, so re-run the job after setting it.
- **The cut assembles them.** On the release branch,
  `scripts/release/changelog.sh --assemble <package> X.Y.Z YYYY-MM-DD`
  writes the version's section, moves the link references on and `git rm`s
  the package's fragments. The release `plan` job refuses a tag whose
  package still holds a fragment (`check_changelog_fragments`).
- **The release window holds a package's fragments back.** While the newest
  dated section of a package has no tag, `scripts/checks/release-window.sh`
  refuses a tree that holds a fragment of that package.

## Security entries

Regulation (EU) 2024/2847 Annex I Part II(2), (4) and (8), checked by
`scripts/checks/changelog-security.sh` over each preview on every pull
request and over the section being cut in the release `plan` job: a Security
section beside other changes opens with its reason, and every Security entry
names its `GHSA-` advisory or an existing `security/vex/` statement
(`docs/release.md`, Security entries).
