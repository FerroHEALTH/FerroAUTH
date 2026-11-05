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
# reads a pending section and a dated one alike (no specification governs
# this: our own design).
#
# Usage: scripts/checks/crate-version-guard.sh <base-ref> [head-ref]
# Exit 0 when the versions, the lock and the changelogs agree, 1 on a
# finding, 2 on a usage error.
set -euo pipefail

# shellcheck source=scripts/lib/guard-args.sh
. "$(dirname "$0")/../lib/guard-args.sh"
readonly GRAMMAR="<base-ref> [head-ref]"
guard_known_flags "$GRAMMAR" "" "$@"
[[ "$#" -ge 1 && "$#" -le 2 && -n "${1:-}" ]] || guard_usage "$GRAMMAR"

cd "$(dirname "$0")/../.."

base="$1"
head="${2:-HEAD}"

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

# Each file is read whole into a variable before a reader sees it: a reader
# that stops early (`awk … exit`, `grep -q`) on a pipe from `git show` can
# kill it with SIGPIPE, which pipefail reports as a failed check.
head_manifest="$(git show "$head:Cargo.toml")"
head_lock="$(git show "$head:Cargo.lock")"
want="$(workspace_version <<< "$head_manifest")"
# The base has no manifest before the workspace's first change.
base_manifest="$(git show "$base:Cargo.toml" 2> /dev/null || true)"
was="$(workspace_version <<< "$base_manifest")"
locked="$(locked_version ferrohealth-smart <<< "$head_lock")"

failed=0
if [[ -z "$want" ]]; then
  echo "crate-version-guard: Cargo.toml declares no [workspace.package] version" >&2
  exit 1
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

agreed=""
own_line ferrohealth-authz
own_line ferrohealth-session

[[ "$failed" -eq 0 ]] || exit 1
echo "crate-version-guard: version $want, the lock and the changelog agree$agreed"
