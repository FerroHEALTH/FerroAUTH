#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The changelog guard (no specification governs it: our own design): a pull
# request that changes a user-visible surface records its effect as a
# fragment under changelog.d/<package>/ (changelog.d/README.md).
# scripts/release/changelog.sh --check judges the fragment's form; this guard
# asks whether there is one, and refuses a change that writes an entry under
# [Unreleased], or under a pending `## [X.Y.Z] - Unreleased` section, of any
# of the four changelogs, since those sections are what two open pull
# requests used to conflict on.
#
#   changelog-guard.sh [--waived] <base-ref> [head-ref]
#   changelog-guard.sh --self-test
#
# The user-visible surfaces are app/, crates/, docker/, the compose files and
# the root Cargo manifest and lock file; a change that touches none needs no
# entry. An edit of a changelog outside those sections (the release cut, or a
# correction of a released section) counts as the change's record. --waived
# is the CI form when the `no-changelog` label is set: the entry is not
# required, and an entry written under [Unreleased] is still refused. This
# script reads no labels.
#
# The change is what the head added since it forked from the base, read from
# the diff against the merge base of the two, so a fragment that reached the
# base after the fork is never counted as the change's own. With no head-ref
# the guard reads HEAD and says on stderr when the working tree holds an
# uncommitted change, since its verdict reads none.
#
# Exit 0 when the change passes, 1 when it carries no entry or writes under
# [Unreleased], and 2 on a usage error or a base and head with no merge base.
set -euo pipefail

readonly SURFACES='^(app/|crates/|docker/|compose[^/]*\.yaml$|Cargo\.toml$|Cargo\.lock$)'
readonly CHANGELOGS=(app/ferrosmart/CHANGELOG.md crates/ferrohealth-smart/CHANGELOG.md
  crates/ferrohealth-authz/CHANGELOG.md crates/ferrohealth-session/CHANGELOG.md)

# written FORK HEAD FILE: prints each non-blank line the change adds to the
# body of [Unreleased] or of a pending `- Unreleased` section of FILE at HEAD.
# A body runs from its heading to the next version heading or the link
# reference block.
written() {
  local fork="$1" head="$2" file="$3" ranges
  git cat-file -e "$head:$file" 2> /dev/null || return 0
  ranges="$(git show "$head:$file" | awk '
    function close_body(to) { if (open) print open, to; open = 0 }
    /^## \[/ {
      close_body(NR - 1)
      if ($0 ~ /^## \[Unreleased\][[:space:]]*$/ || $0 ~ /^## \[[^]]+\] - Unreleased[[:space:]]*$/) open = NR + 1
      next
    }
    /^\[[^]]+\]: / { close_body(NR - 1) }
    END { close_body(NR) }
  ' | tr '\n' ' ')"
  [[ -n "$ranges" ]] || return 0
  git diff --no-renames -U0 "$fork" "$head" -- "$file" | awk -v ranges="$ranges" -v file="$file" '
    BEGIN {
      m = split(ranges, r, " ")
      n = 0
      for (i = 1; i < m; i += 2) { n++; from[n] = r[i]; to[n] = r[i + 1] }
    }
    /^@@ / {
      split($3, range, ",")
      line = substr(range[1], 2) + 0
      next
    }
    /^\+\+\+ / { next }
    /^\+/ {
      text = substr($0, 2)
      if (text ~ /[^[:space:]]/ && text !~ /^## \[/) {
        for (i = 1; i <= n; i++) if (line >= from[i] && line <= to[i]) { print "  " file ":" line ": " text; break }
      }
      line++
    }
  '
}

# The self-test builds a stub repository in a temporary directory, with a copy
# of this script in it, and runs the guard there as CI does: the base is
# main's tip and the head is the branch.
self_test() {
  local script status
  # Global, so the EXIT trap still sees it after the function returns.
  work="$(mktemp -d)"
  # git writes its objects read-only, so the tree is made writable before it
  # is removed.
  trap 'chmod -R u+w "$work" && rm -r -- "$work"' EXIT
  script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  mkdir -p "$work/scripts/checks" "$work/changelog.d/ferrosmart" "$work/changelog.d/ferrohealth-authz" \
    "$work/app/ferrosmart/src" "$work/crates/ferrohealth-authz/src" "$work/docs"
  cp "$script" "$work/scripts/checks/changelog-guard.sh"
  local smart="$work/app/ferrosmart/CHANGELOG.md" authz="$work/crates/ferrohealth-authz/CHANGELOG.md"

  # A repository of its own, so no global hook, signing key or identity of the
  # caller's reaches it.
  stub_git() {
    git -C "$work" -c user.name=self-test -c user.email=self-test@example.org \
      -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"
  }
  commit() {
    local message="$1"
    stub_git add -A
    stub_git commit -q -m "$message"
  }
  branch() {
    local name="$1"
    stub_git checkout -q main
    stub_git checkout -q -b "$name"
  }
  code() { echo 'more code' >> "$work/app/ferrosmart/src/code.txt"; }
  # changelog FILE TEXT: FILE with TEXT as the body of [Unreleased].
  changelog() {
    printf '# Changelog\n\n## [Unreleased]\n%s\n## [1.0.0] - 2026-10-01\n\n### Added\n\n- The first release.\n\n[Unreleased]: https://example.org/r/compare/x-v1.0.0...HEAD\n' \
      "$2" > "$1"
  }
  # expect NAME WANT BRANCH [FLAG]: the guard over BRANCH against main exits
  # WANT.
  expect() {
    local name=$1 want=$2 branch=$3 flag=${4:-}
    status=0
    (cd "$work" && bash scripts/checks/changelog-guard.sh ${flag:+"$flag"} "${base_ref:-main}" "$branch") > "$work/out" 2>&1 || status=$?
    if [[ "$status" -ne "$want" ]]; then
      echo "changelog-guard: self-test failed: $name exited $status, wanted $want." >&2
      cat "$work/out" >&2
      exit 1
    fi
  }
  says() {
    local name=$1 text=$2
    grep -q "$text" "$work/out" || {
      echo "changelog-guard: self-test failed: $name did not say \"$text\"." >&2
      cat "$work/out" >&2
      exit 1
    }
  }

  stub_git init -q -b main
  changelog "$smart" ''
  changelog "$authz" ''
  printf 'The fragment format.\n' > "$work/changelog.d/README.md"
  printf -- '- An entry already released.\n' > "$work/changelog.d/ferrosmart/1-old.added.md"
  echo 'code' > "$work/app/ferrosmart/src/code.txt"
  echo 'a policy' > "$work/crates/ferrohealth-authz/src/lib.rs"
  echo 'a page' > "$work/docs/page.md"
  commit "the fork point"

  branch fragment
  code
  printf -- '- An entry.\n' > "$work/changelog.d/ferrosmart/2-new.added.md"
  commit "a change with a fragment"
  branch unreleased
  code
  printf -- '- An entry.\n' > "$work/changelog.d/ferrosmart/2-new.added.md"
  changelog "$authz" $'\n### Added\n\n- An entry written into the changelog.\n'
  commit "a change with a fragment that also writes under [Unreleased]"
  branch pending
  code
  printf '# Changelog\n\n## [Unreleased]\n\n## [1.1.0] - Unreleased\n\n### Changed\n\n- Breaking: an entry.\n\n## [1.0.0] - 2026-10-01\n\n### Added\n\n- The first release.\n\n[Unreleased]: https://example.org/r/compare/x-v1.0.0...HEAD\n' \
    > "$smart"
  printf -- '- An entry.\n' > "$work/changelog.d/ferrosmart/2-new.changed.md"
  commit "a change that writes under a pending section"
  branch pending-heading
  code
  printf '# Changelog\n\n## [Unreleased]\n\n## [1.1.0] - Unreleased\n\n## [1.0.0] - 2026-10-01\n\n### Added\n\n- The first release.\n\n[Unreleased]: https://example.org/r/compare/x-v1.0.0...HEAD\n' \
    > "$smart"
  printf -- '- Breaking: an entry.\n' > "$work/changelog.d/ferrosmart/2-new.changed.md"
  commit "a breaking change that opens an empty pending section"
  branch cut
  code
  stub_git rm -q -- changelog.d/ferrosmart/1-old.added.md
  printf '# Changelog\n\n## [Unreleased]\n\n## [1.1.0] - 2026-10-02\n\n### Added\n\n- An entry already released.\n\n## [1.0.0] - 2026-10-01\n\n### Added\n\n- The first release.\n\n[Unreleased]: https://example.org/r/compare/x-v1.1.0...HEAD\n' \
    > "$smart"
  commit "the release cut"
  branch none
  code
  commit "a change with no entry"
  branch crate
  echo 'another policy' >> "$work/crates/ferrohealth-authz/src/lib.rs"
  commit "a change to a crate with no entry"
  branch invisible
  echo 'a clearer page' >> "$work/docs/page.md"
  commit "a change to no user-visible surface"
  branch readme
  code
  echo 'A clearer note.' >> "$work/changelog.d/README.md"
  commit "a change to the README alone"
  branch reworded
  code
  printf -- '- An entry, reworded.\n' > "$work/changelog.d/ferrosmart/1-old.added.md"
  commit "a change that rewords a fragment it did not add"
  branch moved
  changelog "$authz" $'\n### Fixed\n\n- An entry a change moves out.\n'
  commit "an entry under [Unreleased]"
  stub_git checkout -q -b moved-out
  code
  changelog "$authz" ''
  printf -- '- An entry a change moves out.\n' > "$work/changelog.d/ferrohealth-authz/3-moved.fixed.md"
  commit "the entry moves into a fragment"

  stub_git checkout -q main
  printf -- '- An entry from main.\n' > "$work/changelog.d/ferrosmart/4-main.fixed.md"
  commit "main gains a fragment after every branch forked"

  expect "a change that adds a fragment" 0 fragment
  says "the fragment" 'changelog.d/ferrosmart/2-new.added.md'
  expect "a change that writes under [Unreleased]" 1 unreleased
  says "the [Unreleased] refusal" 'crates/ferrohealth-authz/CHANGELOG.md:7'
  expect "a waived change that writes under [Unreleased]" 1 unreleased --waived
  expect "a change that writes under a pending section" 1 pending
  says "the pending refusal" 'Breaking: an entry'
  expect "a breaking change that opens an empty pending section" 0 pending-heading
  expect "the release cut" 0 cut
  expect "a change with no entry, behind a main that gained a fragment" 1 none
  says "the refusal" 'no changelog entry'
  expect "a waived change with no entry" 0 none --waived
  expect "a change to a crate with no entry" 1 crate
  expect "a change to no user-visible surface" 0 invisible
  expect "a change to the README alone" 1 readme
  expect "a change that rewords a fragment it did not add" 1 reworded
  base_ref=moved expect "a change that moves an [Unreleased] entry into a fragment" 0 moved-out
  says "the moved entry" "adds the fragment"

  stub_git checkout -q main
  echo 'an uncommitted change' >> "$work/app/ferrosmart/src/code.txt"
  status=0
  (cd "$work" && bash scripts/checks/changelog-guard.sh main) > "$work/out" 2>&1 || status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "changelog-guard: self-test failed: an uncommitted change exited $status, wanted 0." >&2
    cat "$work/out" >&2
    exit 1
  fi
  says "an uncommitted change" 'uncommitted'
  echo "changelog-guard: self-test passed."
}

if [[ "${1:-}" = "--self-test" && $# -eq 1 ]]; then
  self_test
  exit 0
fi

cd "$(dirname "$0")/../.."

waived=0
if [[ "${1:-}" = "--waived" ]]; then
  waived=1
  shift
fi
if [[ $# -lt 1 || $# -gt 2 || -z "${1:-}" || "${1:-}" = -* ]]; then
  echo "usage: changelog-guard.sh [--waived] <base-ref> [head-ref] | --self-test" >&2
  exit 2
fi
base="$1"
head="${2:-HEAD}"
if [[ $# -eq 1 && -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  echo "changelog-guard: the working tree holds uncommitted changes, which this verdict does not read; commit them and run the guard again." >&2
fi

if ! fork="$(git merge-base "$base" "$head")"; then
  echo "changelog-guard: $base and $head have no merge base; check out the full history (fetch-depth: 0)." >&2
  exit 2
fi

lines=""
for file in "${CHANGELOGS[@]}"; do
  lines+="$(written "$fork" "$head" "$file")"
  [[ -z "$lines" || "$lines" == *$'\n' ]] || lines+=$'\n'
done
if [[ -n "$lines" ]]; then
  echo "::error::the change writes under [Unreleased] or a pending '- Unreleased' section of a changelog; move each entry into a fragment, changelog.d/<package>/<issue>-<kebab-slug>.<section>.md, as changelog.d/README.md describes:" >&2
  printf '%s' "$lines" >&2
  exit 1
fi

if [[ "$waived" -eq 1 ]]; then
  echo "changelog-guard: waived; the change writes nothing under [Unreleased]."
  exit 0
fi

touched=$(git diff --no-renames --name-only "$fork" "$head")
if ! grep -qE "$SURFACES" <<<"$touched"; then
  echo "changelog-guard: the change touches no user-visible surface; no entry is required."
  exit 0
fi

# A rename is read as a removal and an addition, so a fragment renamed into
# place counts as added and one renamed away does not.
added="$(git diff --no-renames --name-only --diff-filter=A "$fork" "$head" -- 'changelog.d/*/*')"
if [[ -n "$added" ]]; then
  echo "changelog-guard: the change adds the fragment(s):"
  while IFS= read -r path; do echo "  $path"; done <<<"$added"
  exit 0
fi
if [[ -n "$(git diff --name-only "$fork" "$head" -- "${CHANGELOGS[@]}")" ]]; then
  echo "changelog-guard: the change edits a changelog outside [Unreleased]."
  exit 0
fi
echo "::error::no changelog entry: the change touches a user-visible surface (app/, crates/, docker/, the compose files, the root Cargo.toml and Cargo.lock); add a fragment, changelog.d/<package>/<issue>-<kebab-slug>.<section>.md, as changelog.d/README.md describes, or apply the 'no-changelog' label when the change has no user-visible effect." >&2
exit 1
