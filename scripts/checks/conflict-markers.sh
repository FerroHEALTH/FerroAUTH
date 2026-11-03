#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# Conflict-marker guard: no tracked text file holds a line git writes for an
# unresolved merge conflict, `<<<<<<<`, `=======` or `>>>>>>>` at the start
# of a line, alone or before a space (#191). No specification governs this:
# our own design.
#
# The vendored specification corpora under docs/specs/ are kept verbatim
# (.claude/rules/vendored-inputs.md), so a line there is upstream content and
# is not read.
#
#   scripts/checks/conflict-markers.sh             every tracked text file
#   scripts/checks/conflict-markers.sh --staged [dir]  the files staged for
#                                       commit in the checkout holding dir
#   scripts/checks/conflict-markers.sh --self-test
#
# Exit 0 when no file holds a marker, 1 naming each file and line that does,
# 2 on a usage error.

set -euo pipefail

readonly MARKER='^(<<<<<<<|=======|>>>>>>>)( |$)'
readonly SKIPPED=':(exclude)docs/specs/'

# Lists the marker lines of the tree at $1: the staged blobs with `--cached`
# when $2 is `staged`, the working tree otherwise. Prints `file:line` only,
# never the line's text.
scan() {
  local tree="$1" mode="$2"
  local -a cached=()
  [[ "$mode" == staged ]] && cached=(--cached)
  git -C "$tree" grep ${cached[@]+"${cached[@]}"} -nIE "$MARKER" -- . "$SKIPPED" |
    awk -F: '{ print $1 ":" $2 }' || true
}

check() {
  local tree="$1" mode="$2" found
  found="$(scan "$tree" "$mode")"
  if [[ -n "$found" ]]; then
    echo "conflict-markers: an unresolved merge conflict is left in:" >&2
    printf '%s\n' "$found" | sed 's/^/  /' >&2
    echo "resolve each conflict and remove its marker lines." >&2
    return 1
  fi
  echo "conflict-markers: OK, no tracked file holds a conflict marker."
}

self_test() {
  local work tree
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN
  tree="$work/repo"
  git init -q "$tree"
  fail() {
    echo "conflict-markers: self-test FAILED: $*" >&2
    exit 1
  }
  printf 'clean\n========\nnot <<<<<<< at the start\n' >"$tree/clean.md"
  git -C "$tree" add clean.md
  check "$tree" tree >/dev/null 2>&1 || fail "a clean tree was refused"
  for marker in '<<<<<<< HEAD' '=======' '>>>>>>> 1234567 (a commit)'; do
    printf 'before\n%s\nafter\n' "$marker" >"$tree/conflict.md"
    git -C "$tree" add conflict.md
    if check "$tree" tree >/dev/null 2>"$work/err"; then
      fail "the marker '$marker' passed"
    fi
    grep -q 'conflict.md:2' "$work/err" || fail "the refusal did not name the file and line: $(cat "$work/err")"
    grep -qF -- "$marker" "$work/err" && fail "the refusal quoted the line"
    check "$tree" staged >/dev/null 2>&1 && fail "the staged marker '$marker' passed"
  done
  git -C "$tree" rm -q --cached conflict.md
  rm "$tree/conflict.md"
  mkdir -p "$tree/docs/specs/rfc"
  printf 'title\n=======\n' >"$tree/docs/specs/rfc/text.txt"
  git -C "$tree" add docs/specs/rfc/text.txt
  check "$tree" tree >/dev/null 2>&1 || fail "a vendored corpus line was read"
  echo "conflict-markers: self-test OK (each marker refused by file and line, staged files read, a longer rule and a marker past the line start passed, docs/specs/ skipped)."
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
case "${1:-}" in
  "") check "$root" tree ;;
  --staged) check "$(git -C "${2:-$root}" rev-parse --show-toplevel)" staged ;;
  --self-test) self_test ;;
  *)
    echo "usage: $0 [--staged | --self-test]" >&2
    exit 2
    ;;
esac
