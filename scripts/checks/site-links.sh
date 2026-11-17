#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The site link guard: every internal link and anchor of the published site
# resolves (no specification governs this: our own design). It lints the
# book's sources with mdbook-lint (.mdbook-lint.toml), assembles the site the
# way the Docs workflow does (scripts/site/assemble.sh, the landing page at
# the root and the book under /docs/) into a temporary directory, and runs
# lychee offline over every page with --include-fragments, so a link to a
# page that does not exist and a link to an anchor a page does not carry both
# fail. It then checks README.md the same way, against the repository tree
# GitHub renders it in. --offline skips every http(s) link: the guard sends
# no request anywhere.
#
# Usage:
#   scripts/checks/site-links.sh              assemble the site and check it
#   scripts/checks/site-links.sh --self-test  prove a broken anchor and a
#                                             missing page fail, a sound
#                                             page passes, and a missing
#                                             tool skips outside CI
# Needs mdbook, mdbook-lint and lychee (the documentation toolchain of
# docs/VERSIONS.md) on PATH. Outside CI (CI unset), a missing one prints a
# SKIP naming it and exits 0; in CI, which installs them all, it fails naming
# it. Exit 1 when a lint, a link or an anchor fails; 0 otherwise.
set -euo pipefail
cd "$(dirname "$0")/../.."

# require TOOL...: when a TOOL is not on PATH, print a SKIP naming it and
# exit 0 outside CI; in CI, where every tool is installed, fail naming it.
require() {
  local tool
  for tool in "$@"; do
    if command -v "$tool" > /dev/null 2>&1; then
      continue
    fi
    if [[ -n "${CI:-}" ]]; then
      echo "::error::site-links: $tool is not on PATH, and CI installs it" >&2
      exit 1
    fi
    echo "SKIP: site-links: $tool is not on PATH; install it or add its directory (often ~/.cargo/bin) to PATH to run this check"
    exit 0
  done
}

# check_html ROOT: lychee over every HTML page under the absolute path ROOT,
# resolving a root-relative link (/docs/...) against ROOT.
check_html() {
  local root=$1
  lychee --offline --include-fragments --no-progress --format compact \
    --root-dir "$root" "$root/**/*.html"
}

# skip_cases WORK: runs this script under a PATH without one tool, with CI
# unset and with CI=true, and returns 1 when a run skips or fails the wrong
# way. It needs no tool of the check.
skip_cases() {
  local work="$1" failed=0 script tool bin missing ci want status pattern
  script="$PWD/scripts/checks/site-links.sh"
  mkdir -p "$work/no-mdbook" "$work/no-lychee"
  printf '#!/bin/sh\nexit 0\n' > "$work/stub"
  chmod +x "$work/stub"
  for tool in dirname grep sed; do
    ln -s "$(command -v "$tool")" "$work/no-mdbook/$tool"
    ln -s "$(command -v "$tool")" "$work/no-lychee/$tool"
  done
  for tool in mdbook mdbook-lint; do
    ln -s "$work/stub" "$work/no-lychee/$tool"
  done
  for bin in no-mdbook no-lychee; do
    missing="${bin#no-}"
    for ci in "" true; do
      want=0
      pattern="SKIP: site-links: $missing is not on PATH"
      if [[ -n "$ci" ]]; then
        want=1
        pattern="::error::site-links: $missing is not on PATH"
      fi
      status=0
      CI="$ci" PATH="$work/$bin" "$BASH" "$script" > "$work/out" 2>&1 || status=$?
      if [[ "$status" -eq "$want" ]] && grep -q -F "$pattern" "$work/out"; then
        echo "  ok: without $missing, CI='$ci' exits $want naming it"
      else
        echo "  FAIL: without $missing, CI='$ci' exited $status, wanted $want naming it" >&2
        sed 's/^/    /' "$work/out" >&2
        failed=1
      fi
    done
  done
  return "$failed"
}

self_test() {
  local work failed=0
  work="$(mktemp -d)"
  # shellcheck disable=SC2064 # expand $work now: the local is gone at EXIT.
  trap "rm -rf '$work'" EXIT
  skip_cases "$work" || failed=1
  if [[ "$failed" -ne 0 ]]; then
    return 1
  fi

  require lychee
  mkdir -p "$work/sound" "$work/anchor" "$work/page"
  printf '<html><body><h2 id="here">x</h2><a href="#here">a</a><a href="/b.html#there">b</a></body></html>\n' > "$work/sound/a.html"
  printf '<html><body><h2 id="there">y</h2><a href="a.html">a</a></body></html>\n' > "$work/sound/b.html"
  cp "$work/sound/"*.html "$work/anchor/"
  printf '<html><body><a href="b.html#nowhere">b</a></body></html>\n' > "$work/anchor/c.html"
  cp "$work/sound/"*.html "$work/page/"
  printf '<html><body><a href="missing.html">m</a></body></html>\n' > "$work/page/c.html"

  if check_html "$work/sound" > /dev/null 2>&1; then
    echo "  ok: a site whose every link and anchor resolves passes"
  else
    echo "  FAIL: a sound site was refused" >&2
    failed=1
  fi
  for case in anchor page; do
    if check_html "$work/$case" > /dev/null 2>&1; then
      echo "  FAIL: a site with a broken $case passed" >&2
      failed=1
    else
      echo "  ok: a site with a broken $case fails"
    fi
  done
  [[ "$failed" -eq 0 ]] && echo "site-links self-test: OK"
  return "$failed"
}

case "${1:-}" in
--self-test)
  self_test
  exit
  ;;
"") ;;
*)
  echo "usage: $0 [--self-test]" >&2
  exit 2
  ;;
esac

require mdbook mdbook-lint lychee

echo "== book sources (mdbook-lint)"
mdbook-lint lint website/book/src

site="$(mktemp -d)"
trap 'rm -rf "$site"' EXIT

scripts/site/assemble.sh "$site/out"
echo "== site links (the assembled site, offline, with anchors)"
check_html "$site/out"
echo "== README links (the repository tree, offline, with anchors)"
lychee --offline --include-fragments --no-progress --format compact README.md
echo "site-links: OK"
