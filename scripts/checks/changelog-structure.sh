#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# Changelog structure guard (Keep a Changelog 1.1.0).
#
# Fails when any release section of a changelog (including [Unreleased])
# violates the Keep a Changelog structure:
#   1. a duplicated `### <Type>` subsection inside one release section
#      (each type appears at most once per section: new entries merge into
#      the existing subsection, they never append a second header);
#   2. a subsection header outside the canonical type set
#      (Added / Changed / Deprecated / Removed / Fixed / Security), plus any
#      type a product adds deliberately in CHANGELOG_EXTRA_TYPES (comma-separated,
#      empty by default; e.g. "Upgrade notes").
#
#   scripts/checks/changelog-structure.sh             every crates/*/CHANGELOG.md
#   scripts/checks/changelog-structure.sh <file>...   each file named
#   scripts/checks/changelog-structure.sh --self-test
#
# Each crate keeps its own changelog and the workspace has none at its root,
# so the run with no argument reads every crate's (#204). Exit 0 when every
# file is clean, 1 naming each finding (or when no crate has a changelog), 2
# on a usage error.
#
# Wired into the CI changelog job; runs unconditionally (the
# `no-changelog` escape label waives the entry REQUIREMENT, never the
# structural validity of the file).
set -euo pipefail

# shellcheck source=scripts/lib/guard-args.sh
. "$(dirname "$0")/../lib/guard-args.sh"
guard_known_flags "[<file>... | --self-test]" "--self-test" "$@"

# Checks the one changelog $1.
check_file() {
  local file="$1"
  # awk, not python: this repository ships no Python, and the check is a line
  # scan over one file, exactly what awk is for. The quote character arrives
  # as a variable because an awk string constant cannot portably escape it.
  awk -v path="$file" -v q="'" -v extra="${CHANGELOG_EXTRA_TYPES:-}" '
    BEGIN {
      allowed = "Added, Changed, Deprecated, Fixed, Removed, Security"
      n_extra = split(extra, extras, /[[:space:]]*,[[:space:]]*/)
      for (i = 1; i <= n_extra; i++) {
        sub(/^[[:space:]]+/, "", extras[i]); sub(/[[:space:]]+$/, "", extras[i])
        if (extras[i] != "") { extra_type[extras[i]] = 1; allowed = allowed ", " extras[i] }
      }
    }
    # A release heading opens a new section and resets what has been seen in it.
    /^## \[/ {
      section = $0
      sub(/^## \[/, "", section)
      sub(/\].*$/, "", section)
      delete seen
      next
    }
    # A subsection heading inside a section: check the type, then the duplicate.
    /^### / && section != "" {
      heading = $0
      sub(/^### /, "", heading)
      sub(/[[:space:]]+$/, "", heading)
      if (heading != "Added" && heading != "Changed" && heading != "Deprecated" \
          && heading != "Removed" && heading != "Fixed" && heading != "Security" \
          && !(heading in extra_type)) {
        errors[++n] = path ":" FNR ": " q "### " heading q " in [" section \
          "] is not a Keep-a-Changelog type (allowed: " allowed ")"
      }
      if (heading in seen) {
        errors[++n] = path ":" FNR ": duplicate " q "### " heading q " in [" \
          section "]: merge the entry into the existing subsection instead of " \
          "adding a second header"
      }
      seen[heading] = 1
    }
    END {
      if (n > 0) {
        print "changelog structure check FAILED:" > "/dev/stderr"
        for (i = 1; i <= n; i++) print "  " errors[i] > "/dev/stderr"
        exit 1
      }
      print "changelog structure OK (" path ")"
    }
  ' "$file"
}

# Checks each file named, every one even after a refusal, and fails when any
# refused.
check_files() {
  local file status=0
  for file in "$@"; do
    check_file "$file" || status=1
  done
  return "$status"
}

# Checks every crates/*/CHANGELOG.md under the workspace root $1.
check_workspace() {
  local root="$1" files=()
  shopt -s nullglob
  files=("$root"/crates/*/CHANGELOG.md)
  shopt -u nullglob
  if [[ "${#files[@]}" -eq 0 ]]; then
    echo "changelog structure check FAILED: no crates/*/CHANGELOG.md under $root" >&2
    return 1
  fi
  check_files "${files[@]}"
}

self_test() {
  local work
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN
  fail() {
    echo "changelog-structure: self-test FAILED: $*" >&2
    exit 1
  }
  mkdir -p "$work/clean/crates/one" "$work/clean/crates/two" "$work/empty/crates/none"
  printf '## [Unreleased]\n\n### Added\n\n- a\n\n## [0.1.0] - 2026-01-01\n\n### Added\n\n- b\n\n### Fixed\n\n- c\n' \
    >"$work/clean/crates/one/CHANGELOG.md"
  cp "$work/clean/crates/one/CHANGELOG.md" "$work/clean/crates/two/CHANGELOG.md"
  check_files "$work/clean/crates/one/CHANGELOG.md" >/dev/null 2>&1 || fail "a clean changelog was refused"
  check_workspace "$work/clean" >"$work/out" 2>&1 || fail "a clean workspace was refused"
  grep -q 'crates/two/CHANGELOG.md' "$work/out" || fail "the workspace run did not read every crate"
  printf '## [Unreleased]\n\n### Added\n\n- a\n\n### Added\n\n- b\n' >"$work/dup.md"
  check_files "$work/dup.md" >/dev/null 2>"$work/err" && fail "a duplicated type passed"
  grep -q 'dup.md:7: duplicate' "$work/err" || fail "the duplicate was not named by file and line"
  printf '## [Unreleased]\n\n### Notes\n\n- a\n' >"$work/type.md"
  check_files "$work/type.md" >/dev/null 2>"$work/err" && fail "a type outside the set passed"
  grep -q "type.md:3: '### Notes'" "$work/err" || fail "the stray type was not named by file and line"
  CHANGELOG_EXTRA_TYPES="Notes" check_files "$work/type.md" >/dev/null 2>&1 || fail "a type CHANGELOG_EXTRA_TYPES adds was refused"
  cp "$work/dup.md" "$work/clean/crates/two/CHANGELOG.md"
  check_workspace "$work/clean" >/dev/null 2>"$work/err" && fail "a workspace with one bad changelog passed"
  grep -q 'crates/two/CHANGELOG.md:7' "$work/err" || fail "the workspace run did not name the bad crate"
  check_workspace "$work/empty" >/dev/null 2>&1 && fail "a workspace with no changelog passed"
  echo "changelog-structure: self-test OK (a clean changelog and workspace passed; a duplicated type, a stray type, a bad crate and a workspace with no changelog refused by file and line)."
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
case "${1:-}" in
  "") check_workspace "$root" ;;
  --self-test)
    [[ "$#" -eq 1 ]] || guard_usage "[<file>... | --self-test]"
    self_test
    ;;
  *) check_files "$@" ;;
esac
