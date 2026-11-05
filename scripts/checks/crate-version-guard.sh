#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The crate version rule (.claude/rules/crates-publishing.md): the workspace
# version is ferrohealth-smart's version and its release tag, so it never
# moves backwards, Cargo.lock carries it for ferrohealth-smart, and
# crates/ferrohealth-smart/CHANGELOG.md has a section for it.
# ferrohealth-authz and ferrohealth-session each keep their own version line in
# their own manifest, released by their own `<crate>-v` tag: it never moves
# backwards, Cargo.lock carries it, and once it moves past the 0.0.0 name
# holder crates/<crate>/CHANGELOG.md has a section for it.
#
# A version moves in the pull request that first needs it: the first breaking
# change after a release moves the minor version, as scripts/checks/semver.sh
# requires, and opens the pending section `## [X.Y.Z] - Unreleased`, which
# the release pull request dates; any other release moves it in the release
# pull request (docs/release.md). Either way the section exists, so this guard
# reads a pending section and a dated one alike. A dated section the change
# adds or dates names a released version: its tag exists, or the change is
# the release pull request of that tag, on the branch `release/<tag>` that
# HEAD_BRANCH names (no specification governs this: our own design).
#
# Usage:
#   scripts/checks/crate-version-guard.sh <base-ref> [head-ref]
#   scripts/checks/crate-version-guard.sh --self-test
#
# HEAD_BRANCH is the pull request's head branch, empty by default. Tags are
# read from the local repository, so a CI checkout fetches them.
# Exit 0 when the versions, the lock and the changelogs agree, 1 on a
# finding, 2 on a usage error.
set -euo pipefail

# shellcheck source=scripts/lib/guard-args.sh
. "$(dirname "$0")/../lib/guard-args.sh"
readonly GRAMMAR="<base-ref> [head-ref] | --self-test"
guard_known_flags "$GRAMMAR" "--self-test" "$@"

# The `version` key of `[workspace.package]` in a Cargo.toml read on stdin.
workspace_version() {
  awk '/^\[workspace\.package\]/{p=1; next} /^\[/{p=0}
       p && /^version[[:space:]]*=/{gsub(/.*=[[:space:]]*"|".*/, ""); print; exit}'
}

# The `version` key of `[package]` in a Cargo.toml read on stdin.
package_version() {
  awk '/^\[package\]/{p=1; next} /^\[/{p=0}
       p && /^version[[:space:]]*=/{gsub(/.*=[[:space:]]*"|".*/, ""); print; exit}'
}

# The version of the package $1 in a Cargo.lock read on stdin.
locked_version() {
  awk -v name="$1" '$0 == "name = \"" name "\"" {p=1; next}
       p && /^version = /{gsub(/version = "|"/, ""); print; exit}'
}

# own_line CRATE: the rule for a crate on its own version line, read from
# its own manifest; prints its version when the manifest names one.
own_line() {
  local crate="$1" manifest="crates/$1/Cargo.toml" changelog="crates/$1/CHANGELOG.md"
  local head_text base_text was is locked newest changelog_text
  head_text="$(git show "$head:$manifest" 2> /dev/null || true)"
  is="$(package_version <<< "$head_text")"
  [[ -n "$is" ]] || return 0
  base_text="$(git show "$base:$manifest" 2> /dev/null || true)"
  was="$(package_version <<< "$base_text")"
  if [[ -n "$was" && "$was" != "$is" ]]; then
    newest="$(printf '%s\n%s\n' "$was" "$is" | sort -V | tail -1)"
    if [[ "$newest" != "$is" ]]; then
      echo "crate-version-guard: $crate moves backwards, $was to $is" >&2
      failed=1
    fi
  fi
  locked="$(locked_version "$crate" <<< "$head_lock")"
  if [[ "$locked" != "$is" ]]; then
    echo "crate-version-guard: Cargo.lock holds $crate ${locked:-<none>}, its manifest $is; run cargo update -w" >&2
    failed=1
  fi
  changelog_text="$(git show "$head:$changelog" 2> /dev/null || true)"
  if [[ "$is" != "0.0.0" ]] && ! grep -qF "## [$is]" <<< "$changelog_text"; then
    echo "crate-version-guard: $changelog has no section for $is" >&2
    failed=1
  fi
  agreed+="; $crate $is agrees"
}

# dated_untagged CRATE CHANGELOG: refuses each dated section the change adds
# or dates in CHANGELOG whose version has no release tag of CRATE, unless
# HEAD_BRANCH is the release branch of that tag. A section left as the base
# has it is history and is not read again.
dated_untagged() {
  local crate="$1" changelog="$2" base_text head_text heading version tag
  base_text="$(git show "$base:$changelog" 2> /dev/null || true)"
  head_text="$(git show "$head:$changelog" 2> /dev/null || true)"
  while IFS= read -r heading; do
    [[ -n "$heading" ]] || continue
    grep -qxF "$heading" <<< "$base_text" && continue
    version="${heading#"## ["}"
    version="${version%%]*}"
    tag="$crate-v$version"
    git rev-parse -q --verify "refs/tags/$tag" > /dev/null && continue
    if [[ "$crate" == ferrohealth-smart ]] && git rev-parse -q --verify "refs/tags/v$version" > /dev/null; then
      continue
    fi
    [[ "${HEAD_BRANCH:-}" == "release/$tag" ]] && continue
    echo "crate-version-guard: $changelog dates [$version], which has no tag $tag; leave it '- Unreleased' until the release pull request, on release/$tag, dates it" >&2
    failed=1
  done < <(grep -E '^## \[[0-9]+\.[0-9]+\.[0-9]+[^]]*\] - [0-9]{4}-[0-9]{2}-[0-9]{2}' <<< "$head_text" || true)
}

# guard BASE HEAD: every rule above, over the repository in the working
# directory; returns 1 on a finding.
guard() {
  base="$1"
  head="$2"
  failed=0
  agreed=""
  # Each file is read whole into a variable before a reader sees it: a reader
  # that stops early (`awk … exit`, `grep -q`) on a pipe from `git show` can
  # kill it with SIGPIPE, which pipefail reports as a failed check.
  local head_manifest want base_manifest was locked newest smart_changelog smart_changelog_text
  head_manifest="$(git show "$head:Cargo.toml")"
  head_lock="$(git show "$head:Cargo.lock")"
  want="$(workspace_version <<< "$head_manifest")"
  # The base has no manifest before the workspace's first change.
  base_manifest="$(git show "$base:Cargo.toml" 2> /dev/null || true)"
  was="$(workspace_version <<< "$base_manifest")"
  locked="$(locked_version ferrohealth-smart <<< "$head_lock")"

  if [[ -z "$want" ]]; then
    echo "crate-version-guard: Cargo.toml declares no [workspace.package] version" >&2
    return 1
  fi

  if [[ -n "$was" && "$was" != "$want" ]]; then
    newest="$(printf '%s\n%s\n' "$was" "$want" | sort -V | tail -1)"
    if [[ "$newest" != "$want" ]]; then
      echo "crate-version-guard: the version moves backwards, $was to $want" >&2
      failed=1
    fi
  fi

  if [[ "$locked" != "$want" ]]; then
    echo "crate-version-guard: Cargo.lock holds ferrohealth-smart ${locked:-<none>}, the workspace $want; run cargo update -w" >&2
    failed=1
  fi

  smart_changelog="crates/ferrohealth-smart/CHANGELOG.md"
  smart_changelog_text="$(git show "$head:$smart_changelog" 2> /dev/null || true)"
  if ! grep -qF "## [$want]" <<< "$smart_changelog_text"; then
    echo "crate-version-guard: $smart_changelog has no section for $want" >&2
    failed=1
  fi

  own_line ferrohealth-authz
  own_line ferrohealth-session
  dated_untagged ferrohealth-smart crates/ferrohealth-smart/CHANGELOG.md
  dated_untagged ferrohealth-authz crates/ferrohealth-authz/CHANGELOG.md
  dated_untagged ferrohealth-session crates/ferrohealth-session/CHANGELOG.md

  [[ "$failed" -eq 0 ]] || return 1
  echo "crate-version-guard: version $want, the lock and the changelog agree$agreed"
}

# The self-test: a throwaway repository with one crate on each version line,
# proving the tag rule passes and refuses what it claims to.
self_test() {
  local work fails=0 out rc
  work="$(mktemp -d)"
  # shellcheck disable=SC2064 # expand now: $work is local and gone at EXIT time
  trap "rm -rf '$work'" EXIT
  (
    cd "$work"
    git init -q
    git config user.email self-test@example.invalid
    git config user.name self-test
    git config commit.gpgsign false
    git config tag.gpgsign false
    mkdir -p crates/ferrohealth-smart crates/ferrohealth-authz crates/ferrohealth-session
    printf '[workspace.package]\nversion = "1.1.0"\n' > Cargo.toml
    printf 'name = "ferrohealth-smart"\nversion = "1.1.0"\n\nname = "ferrohealth-authz"\nversion = "0.2.0"\n\nname = "ferrohealth-session"\nversion = "0.3.0"\n' > Cargo.lock
    printf '[package]\nversion = "0.2.0"\n' > crates/ferrohealth-authz/Cargo.toml
    printf '[package]\nversion = "0.3.0"\n' > crates/ferrohealth-session/Cargo.toml
    printf '## [Unreleased]\n\n## [1.1.0] - Unreleased\n\n## [1.0.0] - 2026-01-01\n\n## [0.9.0] - 2025-12-01\n' > crates/ferrohealth-smart/CHANGELOG.md
    printf '## [Unreleased]\n\n## [0.2.0] - 2026-01-01\n' > crates/ferrohealth-authz/CHANGELOG.md
    printf '## [Unreleased]\n\n## [0.3.0] - 2026-01-01\n' > crates/ferrohealth-session/CHANGELOG.md
    git add -A && git commit -q -m base
    git tag ferrohealth-smart-v1.0.0
    git tag ferrohealth-authz-v0.2.0
    git tag ferrohealth-session-v0.3.0
  ) || { echo "crate-version-guard self-test: the fixture repository could not be built" >&2; exit 1; }

  # expect NAME WANT_RC NEEDLE BRANCH BODY: commits BODY as the smart
  # changelog over the base and runs the guard from the base to it.
  expect() {
    local name="$1" want="$2" needle="$3" branch="$4" body="$5"
    (
      cd "$work"
      git checkout -q --detach "$(git rev-list --max-parents=0 HEAD | tail -1)"
      printf '%b' "$body" > crates/ferrohealth-smart/CHANGELOG.md
      git commit -q -a --allow-empty -m "$name"
    )
    set +e
    out="$(cd "$work" && HEAD_BRANCH="$branch" guard "$(git -C "$work" rev-list --max-parents=0 HEAD | tail -1)" HEAD 2>&1)"
    rc=$?
    set -e
    if [[ "$rc" != "$want" || "$out" != *"$needle"* ]]; then
      echo "crate-version-guard self-test: $name: exit $rc (want $want), output: $out" >&2
      fails=$((fails + 1))
    fi
  }

  expect "a pending section and history" 0 "agree" "" \
    '## [Unreleased]\n\n## [1.1.0] - Unreleased\n\n- an entry\n\n## [1.0.0] - 2026-01-01\n\n## [0.9.0] - 2025-12-01\n'
  expect "a section dated outside its release pull request" 1 "dates [1.1.0], which has no tag ferrohealth-smart-v1.1.0" "" \
    '## [Unreleased]\n\n## [1.1.0] - 2026-02-01\n\n## [1.0.0] - 2026-01-01\n\n## [0.9.0] - 2025-12-01\n'
  expect "a section dated on another release branch" 1 "has no tag ferrohealth-smart-v1.1.0" "release/ferrohealth-smart-v1.2.0" \
    '## [Unreleased]\n\n## [1.1.0] - 2026-02-01\n\n## [1.0.0] - 2026-01-01\n\n## [0.9.0] - 2025-12-01\n'
  expect "the release pull request dates its section" 0 "agree" "release/ferrohealth-smart-v1.1.0" \
    '## [Unreleased]\n\n## [1.1.0] - 2026-02-01\n\n## [1.0.0] - 2026-01-01\n\n## [0.9.0] - 2025-12-01\n'
  expect "a tagged section redated" 0 "agree" "" \
    '## [Unreleased]\n\n## [1.1.0] - Unreleased\n\n## [1.0.0] - 2026-01-02\n\n## [0.9.0] - 2025-12-01\n'
  expect "a dated section added for an untagged version" 1 "dates [1.0.1]" "" \
    '## [Unreleased]\n\n## [1.1.0] - Unreleased\n\n## [1.0.1] - 2026-01-05\n\n## [1.0.0] - 2026-01-01\n\n## [0.9.0] - 2025-12-01\n'

  if [[ "$fails" -gt 0 ]]; then
    echo "crate-version-guard self-test FAILED ($fails case(s))" >&2
    exit 1
  fi
  echo "crate-version-guard self-test OK"
}

if [[ "${1:-}" == "--self-test" ]]; then
  [[ "$#" -eq 1 ]] || guard_usage "$GRAMMAR"
  self_test
  exit 0
fi
[[ "$#" -ge 1 && "$#" -le 2 && -n "${1:-}" ]] || guard_usage "$GRAMMAR"
cd "$(dirname "$0")/../.."
guard "$1" "${2:-HEAD}"
