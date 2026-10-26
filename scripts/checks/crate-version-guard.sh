#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The crate version rule (.claude/rules/crates-publishing.md): the workspace
# version is ferrohealth-smart's version and the `v` release tag, so it never
# moves backwards, Cargo.lock carries it for ferrohealth-smart, and
# crates/ferrohealth-smart/CHANGELOG.md has a section for it. ferrohealth-authz keeps its own version
# line in its own manifest, released by the `ferrohealth-authz-v` tag: it never
# moves backwards, Cargo.lock carries it, and once it moves past the 0.0.0 name
# holder crates/ferrohealth-authz/CHANGELOG.md has a section for it. A change
# that moves a version is a release change and moves all three together (no
# specification governs this: our own design).
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

authz_manifest="crates/ferrohealth-authz/Cargo.toml"
authz_changelog="crates/ferrohealth-authz/CHANGELOG.md"
authz_head="$(git show "$head:$authz_manifest" 2> /dev/null || true)"
authz_want="$(package_version <<< "$authz_head")"
if [[ -n "$authz_want" ]]; then
  authz_base="$(git show "$base:$authz_manifest" 2> /dev/null || true)"
  authz_was="$(package_version <<< "$authz_base")"
  if [[ -n "$authz_was" && "$authz_was" != "$authz_want" ]]; then
    newest="$(printf '%s\n%s\n' "$authz_was" "$authz_want" | sort -V | tail -1)"
    if [[ "$newest" != "$authz_want" ]]; then
      echo "crate-version-guard: ferrohealth-authz moves backwards, $authz_was to $authz_want" >&2
      failed=1
    fi
  fi
  authz_locked="$(locked_version ferrohealth-authz <<< "$head_lock")"
  if [[ "$authz_locked" != "$authz_want" ]]; then
    echo "crate-version-guard: Cargo.lock holds ferrohealth-authz ${authz_locked:-<none>}, its manifest $authz_want; run cargo update -w" >&2
    failed=1
  fi
  authz_changelog_text="$(git show "$head:$authz_changelog" 2> /dev/null || true)"
  if [[ "$authz_want" != "0.0.0" ]] && ! grep -qF "## [$authz_want]" <<< "$authz_changelog_text"; then
    echo "crate-version-guard: $authz_changelog has no section for $authz_want" >&2
    failed=1
  fi
fi

[[ "$failed" -eq 0 ]] || exit 1
echo "crate-version-guard: version $want, the lock and the changelog agree${authz_want:+; ferrohealth-authz $authz_want agrees}"
