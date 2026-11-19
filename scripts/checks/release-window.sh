#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# Release-window guard: for each package, while the newest dated
# `## [X.Y.Z] - YYYY-MM-DD` section of its changelog has no pushed tag
# <package>-vX.Y.Z, changelog.d/<package>/ holds no fragment.
#
# A package's window opens when its release pull request assembles the
# fragments into the version's section and closes when the tag is pushed. A
# fragment that reaches a tree inside the window would sit unassembled on the
# commit to be tagged, which the release plan refuses. So the guard fails the
# release pull request whose merge group carries a fragment of its package
# that landed after its assembly (merge main in and assemble again), and every
# pull request with a fragment of that package merged while the cut is
# untagged (it waits for the tag). A fragment of another package passes. No
# specification governs this: our own design, as FerroBRIDGE's.
#
# A tag missing locally is asked of origin; a failure to ask fails the guard.
#
# Usage:
#   scripts/checks/release-window.sh
#   scripts/checks/release-window.sh --self-test
#
# Exit 0 = every window is closed, or open with no fragment. Exit 1 = a
# fragment sits in an open window, or the tags could not be read.
set -euo pipefail

readonly PACKAGES=(ferrosmart ferrohealth-smart ferrohealth-authz ferrohealth-session)

changelog_of() {
  case "$1" in
  ferrosmart) echo "app/ferrosmart/CHANGELOG.md" ;;
  *) echo "crates/$1/CHANGELOG.md" ;;
  esac
}

# The fragments under changelog.d/$2/ of the tree at $1, one per line.
fragments() {
  local root="$1" package="$2"
  find "$root/changelog.d/$package" -maxdepth 1 -type f 2>/dev/null | sort
}

# The version of the newest dated section of the changelog $1, or nothing. A
# pending `- Unreleased` section is no release.
newest() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  sed -nE 's/^## \[([0-9]+\.[0-9]+\.[0-9]+)\] - [0-9]{4}-[0-9]{2}-[0-9]{2}.*/\1/p' "$file" | head -n1
}

# 0 when tag $2 exists in the repository at $1 or at its origin, 1 when origin
# has none, 2 when origin cannot be asked.
tagged() {
  local root="$1" tag="$2" rc=0
  git -C "$root" rev-parse -q --verify "refs/tags/$tag" >/dev/null && return 0
  git -C "$root" ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1 || rc=$?
  case "$rc" in
  0) return 0 ;;
  2) return 1 ;;
  *) return 2 ;;
  esac
}

# window ROOT PACKAGE: the guard over one package.
window() {
  local root="$1" package="$2" version tag rc=0 left
  version="$(newest "$root/$(changelog_of "$package")")"
  if [[ -z "$version" ]]; then
    echo "release-window: $package has no released section, so no window is open"
    return 0
  fi
  tag="$package-v$version"
  left="$(fragments "$root" "$package")"
  if [[ -z "$left" ]]; then
    echo "release-window: changelog.d/$package/ holds no fragment"
    return 0
  fi
  tagged "$root" "$tag" || rc=$?
  case "$rc" in
  0)
    echo "release-window: [$version] of $package is tagged $tag, so the window is closed"
    return 0
    ;;
  1) ;;
  *)
    echo "release-window: cannot ask origin whether $tag exists" >&2
    return 1
    ;;
  esac
  {
    echo "release-window: the $tag cut is assembled and not tagged yet, so the release window of $package is open, and changelog.d/$package/ holds:"
    printf '  %s\n' "${left//$root\//}"
    echo "A fragment of $package waits until $tag is pushed; the release pull request merges main in and runs scripts/release/changelog.sh --assemble again (docs/release.md, The release window)."
  } >&2
  return 1
}

guard() {
  local root="$1" package rc=0
  for package in "${PACKAGES[@]}"; do
    window "$root" "$package" || rc=1
  done
  return "$rc"
}

self_test() {
  local script status
  # Global, so the EXIT trap still sees it after the function returns.
  work="$(mktemp -d)"
  # git writes its objects read-only, so the tree is made writable before it
  # is removed.
  trap 'chmod -R u+w "$work" && rm -r -- "$work"' EXIT
  script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  stub_git() {
    git -C "$work/clone" -c user.name=self-test -c user.email=self-test@example.org \
      -c commit.gpgsign=false -c tag.gpgsign=false -c core.hooksPath=/dev/null "$@"
  }
  # changelog PACKAGE HEADING: the package's changelog whose newest section is
  # headed HEADING, above a released 0.9.0.
  changelog() {
    local file
    file="$work/clone/$(changelog_of "$1")"
    mkdir -p "$(dirname "$file")"
    printf '# Changelog\n\n## [Unreleased]\n\n## [%s]\n\n### Added\n\n- A release.\n\n## [0.9.0] - 2026-10-01\n\n### Added\n\n- The first.\n' \
      "$2" >"$file"
  }
  fragment() {
    mkdir -p "$work/clone/changelog.d/$1"
    echo '- A change.' >"$work/clone/changelog.d/$1/$2"
  }
  commit() {
    stub_git add -A
    stub_git commit -q -m "$1"
  }
  expect() {
    local name="$1" want="$2"
    status=0
    (cd "$work/clone" && bash "$script" >"$work/out" 2>&1) || status=$?
    if [[ "$status" != "$want" ]]; then
      echo "release-window: self-test failed: $name exited $status, wanted $want." >&2
      cat "$work/out" >&2
      exit 1
    fi
  }
  git init -q --bare "$work/origin.git"
  git clone -q "$work/origin.git" "$work/clone" 2>/dev/null
  mkdir -p "$work/clone/changelog.d"
  echo '# Changelog fragments' >"$work/clone/changelog.d/README.md"

  local package
  for package in "${PACKAGES[@]}"; do changelog "$package" "1.0.0] - 2026-11-01"; done
  commit "every package at 1.0.0"
  stub_git tag ferrohealth-authz-v1.0.0
  stub_git tag ferrosmart-v1.0.0
  stub_git tag ferrosmart-v0.9.0
  stub_git tag ferrohealth-smart-v1.0.0
  stub_git tag ferrohealth-session-v1.0.0
  stub_git push -q origin HEAD:refs/heads/main --tags
  fragment ferrohealth-authz 2-change.added.md
  commit "feat: a change after the tag"
  expect "a fragment after a pushed tag passes" 0

  stub_git rm -q "changelog.d/ferrohealth-authz/2-change.added.md"
  changelog ferrohealth-authz "1.1.0] - 2026-11-02"
  commit "release: ferrohealth-authz-v1.1.0, the fragments assembled"
  stub_git push -q origin HEAD:refs/heads/main
  expect "an assembled, untagged cut with no fragment passes" 0

  fragment ferrosmart 3-other.added.md
  commit "feat: a fragment of another package between the cut and the tag"
  expect "a fragment of another package passes" 0

  changelog ferrosmart "1.1.0] - Unreleased"
  commit "a breaking change opens a pending section"
  expect "a pending section opens no window" 0

  fragment ferrohealth-authz 4-late.added.md
  commit "feat: a fragment between the cut and the tag"
  expect "a fragment between the cut and the tag is refused" 1
  grep -q 'ferrohealth-authz-v1.1.0 cut' "$work/out" || { cat "$work/out" >&2; echo "release-window: self-test failed: the refusal did not name the tag." >&2; exit 1; }

  stub_git tag ferrohealth-authz-v1.1.0 HEAD~3
  stub_git push -q origin refs/tags/ferrohealth-authz-v1.1.0
  stub_git tag -d ferrohealth-authz-v1.1.0 >/dev/null
  expect "a tag pushed to origin and missing locally closes the window" 0

  git -C "$work/clone" remote set-url origin "$work/missing.git"
  changelog ferrohealth-authz "1.2.0] - 2026-11-03"
  commit "release: ferrohealth-authz-v1.2.0"
  expect "an origin that cannot be asked fails" 1
  echo "release-window: self-test passed."
}

case "${1:-}" in
--self-test) self_test ;;
"") guard "$(git rev-parse --show-toplevel)" ;;
*)
  echo "usage: $0 [--self-test]" >&2
  exit 2
  ;;
esac
