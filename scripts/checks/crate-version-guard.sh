#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The crate version rule (.claude/rules/crates-publishing.md): the workspace
# version is the library's version and the release tag, so it never moves
# backwards, Cargo.lock carries it for ferrohealth-smart, and CHANGELOG.md has
# a section for it. A change that moves the version is a release change and
# must move all three together (no specification governs this: our own
# design).
#
# Usage: scripts/checks/crate-version-guard.sh <base-ref> [head-ref]
set -euo pipefail
cd "$(dirname "$0")/../.."

base="${1:?usage: crate-version-guard.sh <base-ref> [head-ref]}"
head="${2:-HEAD}"

# The `version` key of `[workspace.package]` in a Cargo.toml read on stdin.
workspace_version() {
  awk '/^\[workspace\.package\]/{p=1; next} /^\[/{p=0}
       p && /^version[[:space:]]*=/{gsub(/.*=[[:space:]]*"|".*/, ""); print; exit}'
}

# The version of the ferrohealth-smart package in a Cargo.lock read on stdin.
locked_version() {
  awk '/^name = "ferrohealth-smart"$/{p=1; next}
       p && /^version = /{gsub(/version = "|"/, ""); print; exit}'
}

want="$(git show "$head:Cargo.toml" | workspace_version)"
# The base has no manifest before the workspace's first change.
was="$(git show "$base:Cargo.toml" 2> /dev/null | workspace_version || true)"
locked="$(git show "$head:Cargo.lock" | locked_version)"

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

if ! git show "$head:CHANGELOG.md" | grep -qF "## [$want]"; then
  echo "crate-version-guard: CHANGELOG.md has no section for $want" >&2
  failed=1
fi

[[ "$failed" -eq 0 ]] || exit 1
echo "crate-version-guard: version $want, the lock and the changelog agree"
