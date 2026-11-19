#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
#
# Changelog fragments (no specification governs this: our own design, the one
# the FerroHEALTH products share). Every change with a user-visible effect adds
# one file under changelog.d/<package>/, so no two pull requests edit the same
# lines of a changelog, and the release cut of a package assembles its
# fragments into its changelog, which follows Keep a Changelog 1.1.0
# (https://keepachangelog.com/en/1.1.0/).
#
# The packages and their changelogs:
#   ferrosmart            app/ferrosmart/CHANGELOG.md
#   ferrohealth-smart     crates/ferrohealth-smart/CHANGELOG.md
#   ferrohealth-authz     crates/ferrohealth-authz/CHANGELOG.md
#   ferrohealth-session   crates/ferrohealth-session/CHANGELOG.md
#
# A fragment is changelog.d/<package>/<issue>-<kebab-slug>.<section>.md, where
# <section> is added, changed, deprecated, removed, fixed or security, and its
# content is one or more Markdown list items exactly as they read in the
# changelog: a line that opens with "- ", continued by lines indented by at
# least two spaces. changelog.d/README.md is the format note.
#
# One more fragment kind, <issue>-<kebab-slug>.security-reason.md, carries the
# line a release's Security section opens with when it ships beside functional
# changes: "Shipped with functional changes because: <reason>" (Regulation
# (EU) 2024/2847 Annex I Part II(2), docs/release.md). It is one paragraph, a
# package holds at most one, and the cut places it first under "### Security".
#
#   changelog.sh --check
#       Validates every fragment's place, name and content. Exit 0 when every
#       one holds, 1 otherwise, naming each defect.
#   changelog.sh --assemble <package> <version> <date>
#       Writes "## [<version>] - <date>" under a fresh, empty [Unreleased] of
#       the package's changelog, holding the entries of [Unreleased] and of a
#       pending "## [<version>] - Unreleased" section followed by the
#       package's fragments, section by section in the Keep a Changelog
#       order; moves the [Unreleased] link reference on to <package>-v<version>
#       and adds the version's; then `git rm`s the fragments. Exit 1 on any
#       defect, with nothing written.
#   changelog.sh --preview <package>
#       Prints the package's changelog with its fragments folded into
#       [Unreleased], as the next cut would write that section; writes nothing.
#   changelog.sh --check-preview
#       Runs scripts/checks/changelog-structure.sh and
#       scripts/checks/changelog-security.sh over the preview of every
#       package, so the release section's rules hold on every pull request.
#   changelog.sh --self-test
#       Proves every mode over a stub repository.
#
# The output is deterministic: fragments are read by section in the order
# above, then by file name in the C locale. Exit 2 on a usage error.
set -euo pipefail
export LC_ALL=C

# The Keep a Changelog 1.1.0 sections, in the order a release lists them.
readonly SECTIONS=(added changed deprecated removed fixed security)
readonly PACKAGES=(ferrosmart ferrohealth-smart ferrohealth-authz ferrohealth-session)
readonly FRAGMENT_DIR=changelog.d
readonly NAME_RE='^[0-9]+-[a-z0-9]+(-[a-z0-9]+)*\.(added|changed|deprecated|removed|fixed|security|security-reason)\.md$'
readonly REASON_PREFIX="Shipped with functional changes because: "

die() {
  echo "changelog: $*" >&2
  exit 1
}

usage() {
  echo "usage: changelog.sh --check | --assemble <package> <version> <date> | --preview <package> | --check-preview | --self-test" >&2
  exit 2
}

# changelog_of PACKAGE: the changelog the package's fragments are cut into.
changelog_of() {
  case "$1" in
  ferrosmart) echo "app/ferrosmart/CHANGELOG.md" ;;
  ferrohealth-smart | ferrohealth-authz | ferrohealth-session) echo "crates/$1/CHANGELOG.md" ;;
  *) return 1 ;;
  esac
}

known_package() {
  changelog_of "$1" > /dev/null || {
    echo "changelog: '$1' is no package; the packages are ${PACKAGES[*]}." >&2
    exit 2
  }
}

# title SECTION: the heading a section carries in a changelog.
title() {
  local section="$1"
  printf '%s%s' "$(tr '[:lower:]' '[:upper:]' <<<"${section:0:1}")" "${section:1}"
}

# content_defect FILE: prints why FILE is no list item, or nothing when it is.
content_defect() {
  local file="$1"
  awk '
    { lines[NR] = $0 }
    END {
      last = NR
      while (last > 0 && lines[last] ~ /^[[:space:]]*$/) last--
      if (last == 0) { print "it is empty"; exit }
      if (lines[1] !~ /^- [^[:space:]]/) { print "line 1 does not open a list item with \"- \""; exit }
      for (i = 2; i <= last; i++) {
        if (lines[i] ~ /^- [^[:space:]]/ || lines[i] ~ /^  +[^[:space:]]/) continue
        if (lines[i] ~ /^[[:space:]]*$/) { print "line " i " is blank inside the entry"; exit }
        print "line " i " neither opens a list item nor continues one indented by two spaces"
        exit
      }
    }
  ' "$file"
}

# reason_defect FILE: prints why FILE is no reason paragraph, or nothing when
# it is one.
reason_defect() {
  local file="$1"
  awk -v prefix="$REASON_PREFIX" '
    { lines[NR] = $0 }
    END {
      last = NR
      while (last > 0 && lines[last] ~ /^[[:space:]]*$/) last--
      if (last == 0) { print "it is empty"; exit }
      if (index(lines[1], prefix) != 1 || lines[1] == prefix) {
        print "line 1 does not open with \"" prefix "<reason>\""
        exit
      }
      for (i = 2; i <= last; i++) {
        if (lines[i] ~ /^[[:space:]]*$/) { print "line " i " is blank inside the reason"; exit }
        if (lines[i] ~ /^[-*+] /) { print "line " i " opens a list item; the reason is one paragraph"; exit }
      }
    }
  ' "$file"
}

# check: every fragment's place, name and content, every defect named.
check() {
  local fail=0 count=0 path name defect package reasons
  [[ -d "$FRAGMENT_DIR" ]] || die "$FRAGMENT_DIR/ is missing"
  for path in "$FRAGMENT_DIR"/* "$FRAGMENT_DIR"/.[!.]*; do
    [[ -e "$path" ]] || continue
    name="${path#"$FRAGMENT_DIR"/}"
    [[ "$name" != README.md ]] || continue
    if [[ ! -d "$path" ]] || ! changelog_of "$name" > /dev/null; then
      echo "changelog: $path is no package directory; a fragment lives under $FRAGMENT_DIR/<package>/, with <package> one of ${PACKAGES[*]}." >&2
      fail=1
    fi
  done
  for package in "${PACKAGES[@]}"; do
    reasons=0
    for path in "$FRAGMENT_DIR/$package"/* "$FRAGMENT_DIR/$package"/.[!.]*; do
      [[ -e "$path" ]] || continue
      name="${path#"$FRAGMENT_DIR/$package"/}"
      if [[ ! -f "$path" ]]; then
        echo "changelog: $path is not a file; a fragment is one file directly under $FRAGMENT_DIR/$package/." >&2
        fail=1
        continue
      fi
      if [[ ! "$name" =~ $NAME_RE ]]; then
        echo "changelog: $path is not named <issue>-<kebab-slug>.<section>.md with <section> one of ${SECTIONS[*]} or security-reason." >&2
        fail=1
        continue
      fi
      if [[ "$name" == *.security-reason.md ]]; then
        reasons=$((reasons + 1))
        defect="$(reason_defect "$path")"
        if [[ -n "$defect" ]]; then
          echo "changelog: $path is not a reason paragraph: $defect." >&2
          fail=1
          continue
        fi
        count=$((count + 1))
        continue
      fi
      defect="$(content_defect "$path")"
      if [[ -n "$defect" ]]; then
        echo "changelog: $path is not a Markdown list item: $defect." >&2
        fail=1
        continue
      fi
      count=$((count + 1))
    done
    if [[ "$reasons" -gt 1 ]]; then
      echo "changelog: $FRAGMENT_DIR/$package/ holds $reasons *.security-reason.md fragments; a release's Security section opens with one reason, so merge them." >&2
      fail=1
    fi
  done
  [[ "$fail" -eq 0 ]] || exit 1
  echo "changelog: $count fragment(s) under $FRAGMENT_DIR/, every one well formed."
}

# sections_of FROM TO DIR LABEL SOURCE: splits lines FROM..TO of $CHANGELOG into
# DIR/<source>.<section>, LABEL naming the lines in a refusal. Text outside a
# known section heading is refused, never dropped.
sections_of() {
  local from="$1" to="$2" dir="$3" label="$4" source="$5"
  [[ "$to" -ge "$from" ]] || return 0
  sed -n "${from},${to}p" "$CHANGELOG" | awk -v dir="$dir" -v label="$label" -v source="$source" '
    /^### / {
      heading = substr($0, 5)
      sub(/[[:space:]]+$/, "", heading)
      section = tolower(heading)
      if (section !~ /^(added|changed|deprecated|removed|fixed|security)$/) {
        print "changelog: " label " has a section \"" heading "\", which Keep a Changelog 1.1.0 does not define." > "/dev/stderr"
        exit 1
      }
      next
    }
    section == "" && /[^[:space:]]/ {
      print "changelog: " label " holds text outside a section heading: " $0 > "/dev/stderr"
      exit 1
    }
    section != "" { print >> (dir "/" source "." section) }
  ' || exit 1
}

# assemble PACKAGE VERSION DATE [preview]: the cut, written to the package's
# changelog in one move. With "preview" it prints the file with the fragments
# folded into [Unreleased] instead, and touches nothing.
assemble() {
  local package="$1" version="$2" date="$3" mode="${4:-cut}" work start end total section file
  local prev base label tag pending pend_end dir="$FRAGMENT_DIR/$package"
  CHANGELOG="$(changelog_of "$package")"
  tag="$package-v$version"
  if [[ "$mode" == cut ]]; then
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "'$version' is not a version such as 0.0.9 or 0.0.9-rc.1"
    [[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "'$date' is not a date written YYYY-MM-DD"
  fi
  [[ -f "$CHANGELOG" ]] || die "$CHANGELOG is missing"
  check > /dev/null

  start="$(grep -n -m1 -E '^## \[Unreleased\][[:space:]]*$' "$CHANGELOG" | cut -d: -f1 || true)"
  [[ -n "$start" ]] || die "$CHANGELOG has no '## [Unreleased]' heading"
  total="$(wc -l < "$CHANGELOG" | tr -d ' ')"
  # A section ends at the next version heading or at the link reference
  # block, whichever comes first.
  end="$(awk -v s="$start" 'NR > s && (/^## \[/ || /^\[[^]]+\]: /) { print NR - 1; exit }' "$CHANGELOG")"
  [[ -n "$end" ]] || end="$total"

  # The pending section a breaking change opened sits directly under
  # [Unreleased]; the cut of its version takes its entries.
  pending=""
  pend_end="$end"
  if [[ "$end" -lt "$total" ]] && sed -n "$((end + 1))p" "$CHANGELOG" | grep -qE '^## \[[^]]+\] - Unreleased[[:space:]]*$'; then
    pending="$(sed -n "$((end + 1))p" "$CHANGELOG" | sed -E 's/^## \[([^]]+)\].*/\1/')"
    pend_end="$(awk -v s="$((end + 1))" 'NR > s && (/^## \[/ || /^\[[^]]+\]: /) { print NR - 1; exit }' "$CHANGELOG")"
    [[ -n "$pend_end" ]] || pend_end="$total"
  fi
  if [[ "$mode" == cut ]]; then
    if [[ -n "$pending" && "$pending" != "$version" ]]; then
      die "$CHANGELOG holds the pending section [$pending] - Unreleased; cut $pending, the version a breaking change opened"
    fi
    if [[ -z "$pending" ]] && awk -v heading="## [$version]" 'index($0, heading) == 1 { found = 1 } END { exit !found }' "$CHANGELOG"; then
      die "$CHANGELOG already has a [$version] section"
    fi
  fi

  label="$(sed -nE 's|^\[([Uu]nreleased)\]: .*/compare/[^/]+\.\.\.HEAD$|\1|p' "$CHANGELOG")"
  prev="$(sed -nE 's|^\[[Uu]nreleased\]: (.*)/compare/([^/]+)\.\.\.HEAD$|\2|p' "$CHANGELOG")"
  base="$(sed -nE 's|^\[[Uu]nreleased\]: (.*)/compare/([^/]+)\.\.\.HEAD$|\1|p' "$CHANGELOG")"
  [[ "$mode" == preview || (-n "$prev" && -n "$base") ]] || die "$CHANGELOG has no '[Unreleased]: <repository>/compare/<tag>...HEAD' link reference"

  work="$(mktemp -d)"
  # Global, so the EXIT trap still sees it after the function returns.
  assemble_work="$work"
  trap 'rm -r -- "$assemble_work"' EXIT

  # In the preview the pending section stays where it is, as the security
  # check reads it beside [Unreleased]; at the cut it is merged.
  sections_of "$((start + 1))" "$end" "$work" "[Unreleased]" unreleased
  if [[ "$mode" == cut && -n "$pending" ]]; then
    sections_of "$((end + 2))" "$pend_end" "$work" "[$pending] - Unreleased" pending
  fi

  # Each section of the release: the entries already in the changelog first,
  # in their order, then the fragments by file name. The Security section
  # opens with the reason fragment, when there is one.
  local fragments=() entries=0 reason=""
  for file in "$dir"/*.security-reason.md; do
    [[ -e "$file" ]] || continue
    reason="$file"
  done
  for section in "${SECTIONS[@]}"; do
    {
      if [[ "$section" == security && -n "$reason" ]]; then
        if cat "$work"/pending.security "$work"/unreleased.security 2> /dev/null | grep -qF "$REASON_PREFIX"; then
          die "$CHANGELOG already opens its Security section with a reason, and $reason gives another; keep one"
        fi
        tracked "$reason" "$mode"
        fragments+=("$reason")
        trim "$reason"
        printf '\n'
      fi
      [[ ! -f "$work/pending.$section" ]] || trim "$work/pending.$section"
      [[ ! -f "$work/unreleased.$section" ]] || trim "$work/unreleased.$section"
      for file in "$dir"/*."$section".md; do
        [[ -e "$file" ]] || continue
        tracked "$file" "$mode"
        fragments+=("$file")
        trim "$file" | name_issue "$file"
      done
    } > "$work/new.$section"
    [[ ! -s "$work/new.$section" ]] || entries=$((entries + 1))
  done
  if [[ -n "$reason" ]] && ! grep -q '^- ' "$work/new.security"; then
    die "$reason gives a reason for a Security section that holds no entry"
  fi

  if [[ "$mode" == preview ]]; then
    sed -n "1,${start}p" "$CHANGELOG"
    for section in "${SECTIONS[@]}"; do
      [[ -s "$work/new.$section" ]] || continue
      printf '\n### %s\n\n' "$(title "$section")"
      cat "$work/new.$section"
    done
    printf '\n'
    [[ "$end" -ge "$total" ]] || sed -n "$((end + 1)),${total}p" "$CHANGELOG"
    return 0
  fi
  [[ "$entries" -gt 0 ]] || die "[$version] would be empty: no fragment under $dir/ and no entry in $CHANGELOG"

  local out="$work/CHANGELOG.md" has_link=0
  if grep -q "^\[$version\]: " "$CHANGELOG"; then has_link=1; fi
  {
    sed -n "1,${start}p" "$CHANGELOG"
    printf '\n## [%s] - %s\n' "$version" "$date"
    for section in "${SECTIONS[@]}"; do
      [[ -s "$work/new.$section" ]] || continue
      printf '\n### %s\n\n' "$(title "$section")"
      cat "$work/new.$section"
    done
    printf '\n'
    if [[ "$pend_end" -lt "$total" ]]; then
      sed -n "$((pend_end + 1)),${total}p" "$CHANGELOG" | awk -v ver="$version" -v tag="$tag" -v prev="$prev" -v base="$base" -v label="$label" -v has_link="$has_link" '
        /^\[[Uu]nreleased\]: / {
          print "[" label "]: " base "/compare/" tag "...HEAD"
          if (!has_link) print "[" ver "]: " base "/compare/" prev "..." tag
          next
        }
        { print }
      '
    fi
  } > "$out"

  cat "$out" > "$CHANGELOG"
  if [[ "${#fragments[@]}" -gt 0 ]]; then
    git rm -q -- "${fragments[@]}"
  fi
  echo "changelog: [$version] - $date of $CHANGELOG assembled from ${#fragments[@]} fragment(s) and the entries it held; review it and commit."
}

# tracked FILE MODE: refuses an untracked fragment at the cut; the preview reads
# the working tree as it stands.
tracked() {
  local file="$1" mode="$2"
  [[ "$mode" == preview ]] && return 0
  git ls-files --error-unmatch -- "$file" > /dev/null 2>&1 || die "$file is not tracked by git; commit it before the cut"
}

# check_preview: the release-section checks over every package's preview, with
# VEX paths resolved against the repository root as at the cut.
check_preview() {
  local dir rc=0 package
  dir="$(mktemp -d)"
  check_preview_dir="$dir"
  trap 'rm -r -- "$check_preview_dir"' EXIT
  for package in "${PACKAGES[@]}"; do
    (assemble "$package" "" "" preview) > "$dir/$package.md" || { rc=1; continue; }
    bash scripts/checks/changelog-structure.sh "$dir/$package.md" || rc=1
    VEX_ROOT="$PWD" CHANGELOG_RULE="${CHANGELOG_RULE:-docs/release.md, Security entries, and changelog.d/README.md for the fragments}" \
      bash scripts/checks/changelog-security.sh --section Unreleased "$dir/$package.md" || rc=1
  done
  return "$rc"
}

# trim FILE: FILE without its leading and trailing blank lines.
trim() {
  local file="$1"
  awk '
    { lines[NR] = $0 }
    END {
      first = 1
      while (first <= NR && lines[first] ~ /^[[:space:]]*$/) first++
      last = NR
      while (last >= first && lines[last] ~ /^[[:space:]]*$/) last--
      for (i = first; i <= last; i++) print lines[i]
    }
  ' "$file"
}

# name_issue FILE: the entries on stdin, each ending its first paragraph with
# the issue the fragment's file name starts with, `(#NNN)`, unless the entry
# already names that issue. A trailing full stop stays last.
name_issue() {
  local issue
  issue="$(basename "$1")"
  issue="${issue%%-*}"
  awk -v issue="$issue" '
    function flush(   i) {
      if (count == 0) return
      if (!named) {
        if (lines[last] ~ /\.$/) {
          lines[last] = substr(lines[last], 1, length(lines[last]) - 1) " (#" issue ")."
        } else {
          lines[last] = lines[last] " (#" issue ")"
        }
      }
      for (i = 1; i <= count; i++) print lines[i]
      count = 0
      named = 0
    }
    /^- / { flush(); paragraph = 1; last = 1 }
    {
      lines[++count] = $0
      if ($0 ~ ("(^|[^/A-Za-z0-9])#" issue "([^0-9]|$)")) named = 1
      if (count > 1) {
        if ($0 ~ /^[[:space:]]+[-*] /) paragraph = 0
        else if (paragraph) last = count
      }
    }
    END { flush() }
  '
}

self_test() {
  local script status entry="- An entry." frag
  # Global, so the EXIT trap still sees it after the function returns.
  work="$(mktemp -d)"
  # git writes its objects read-only, so the tree is made writable before it
  # is removed.
  trap 'chmod -R u+w "$work" && rm -r -- "$work"' EXIT
  script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  frag="$work/$FRAGMENT_DIR/ferrohealth-authz"
  mkdir -p "$work/scripts/release" "$work/scripts/checks" "$work/scripts/lib" "$frag" \
    "$work/crates/ferrohealth-authz" "$work/crates/ferrohealth-smart" "$work/crates/ferrohealth-session" \
    "$work/app/ferrosmart"
  local package
  for package in "${PACKAGES[@]}"; do mkdir -p "$work/$FRAGMENT_DIR/$package"; done
  cp "$script" "$work/scripts/release/changelog.sh"
  # The release-section checks --check-preview runs, from the same tree.
  cp "$(dirname "$script")/../checks/changelog-structure.sh" "$(dirname "$script")/../checks/changelog-security.sh" \
    "$work/scripts/checks/"
  cp "$(dirname "$script")/../lib/guard-args.sh" "$work/scripts/lib/"
  local other
  for other in crates/ferrohealth-smart crates/ferrohealth-session app/ferrosmart; do
    printf '%s\n' '# Changelog' '' '## [Unreleased]' '' '## [0.1.0] - 2026-10-01' '' '### Added' '' '- The first release.' '' \
      '[Unreleased]: https://example.org/r/compare/x-v0.1.0...HEAD' > "$work/$other/CHANGELOG.md"
  done
  local log="$work/crates/ferrohealth-authz/CHANGELOG.md"

  # A repository of its own, so no global hook, signing key or identity of the
  # caller's reaches it.
  stub_git() {
    git -C "$work" -c user.name=self-test -c user.email=self-test@example.org \
      -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"
  }
  flunk() {
    echo "changelog: self-test failed: $*" >&2
    cat "$work/out" >&2
    exit 1
  }
  # expect NAME WANT ARGS...: the script run in the stub exits WANT.
  expect() {
    local name="$1" want="$2"
    shift 2
    status=0
    (cd "$work" && bash scripts/release/changelog.sh "$@") > "$work/out" 2>&1 || status=$?
    [[ "$status" -eq "$want" ]] || flunk "$name exited $status, wanted $want."
  }
  fragment() {
    local name="$1"
    shift
    mkdir -p "$frag"
    printf '%s\n' "$@" > "$frag/$name"
  }
  unfragment() {
    local name="$1"
    rm -- "$frag/$name"
  }

  stub_git init -q -b main
  printf 'The fragment format.\n' > "$work/$FRAGMENT_DIR/README.md"

  # --check: the places, names and contents it accepts, and each it refuses.
  expect "a directory holding only the README and the package directories" 0 --check
  fragment 3-a-change.added.md '- An entry that runs' '  over two lines.' '  - and nests a list item.' \
    '- A second entry of fragment 3, unpunctuated'
  expect "a well-formed fragment beside the README" 0 --check
  printf '%s\n' "$entry" > "$work/$FRAGMENT_DIR/3-loose.added.md"
  expect "a fragment outside a package directory" 1 --check
  grep -q 'no package directory' "$work/out" || flunk "the loose fragment was not named."
  rm -- "$work/$FRAGMENT_DIR/3-loose.added.md"
  mkdir "$work/$FRAGMENT_DIR/ferrohealth-unknown"
  expect "an unknown package directory" 1 --check
  rmdir "$work/$FRAGMENT_DIR/ferrohealth-unknown"
  local bad
  for bad in 3-Upper.added.md a-no-issue.added.md 3-a.unknown.md 3-a.added.txt 3-a_b.fixed.md 3-.fixed.md; do
    fragment "$bad" "$entry"
    expect "the misnamed fragment $bad" 1 --check
    grep -q "$bad is not named" "$work/out" || flunk "the misnamed fragment $bad failed without naming it."
    unfragment "$bad"
  done
  fragment 4-heading.fixed.md '### Fixed' '' "$entry"
  expect "a fragment holding a heading" 1 --check
  unfragment 4-heading.fixed.md
  fragment 4-prose.fixed.md 'A sentence, no list item.'
  expect "a fragment of prose" 1 --check
  unfragment 4-prose.fixed.md
  fragment 4-blank.fixed.md '- One entry.' '' '- Another entry.'
  expect "a fragment with a blank line inside" 1 --check
  grep -q 'line 2 is blank' "$work/out" || flunk "the blank line was not named."
  unfragment 4-blank.fixed.md
  fragment 4-flush.fixed.md '- One entry' 'continued flush left.'
  expect "a fragment continued without indentation" 1 --check
  unfragment 4-flush.fixed.md
  printf '' > "$frag/4-empty.fixed.md"
  expect "an empty fragment" 1 --check
  unfragment 4-empty.fixed.md
  mkdir "$frag/5-dir.added.md"
  expect "a directory named as a fragment" 1 --check
  rmdir "$frag/5-dir.added.md"

  # --assemble: the [Unreleased] entries of a changelog, merged with the
  # package's fragments, section by section and by file name in the C locale,
  # with the links moved to the package's tag. Another package's fragment
  # stays where it is.
  cat > "$log" <<'EOF'
# Changelog

## [Unreleased]

### Added

- An entry written into the changelog
  before the fragments.
- A second entry written into the changelog.

### Fixed

- A fix written into the changelog.

## [0.0.1] - 2026-10-01

### Added

- The first release.

[Unreleased]: https://example.org/r/compare/ferrohealth-authz-v0.0.1...HEAD
[0.0.1]: https://example.org/r/releases/tag/ferrohealth-authz-v0.0.1
EOF
  fragment 12-b.added.md '- Fragment 12-b.' '- Fragment 12-b names another issue (#99) and its own (#12) already.'
  fragment 7-y.changed.md '- Fragment 7-y, beside FerroHEALTH/FerroEHR#7.' '' ''
  fragment 5-x.security.md '- Fragment 5-x.'
  printf '%s\n' '- Another package.' > "$work/$FRAGMENT_DIR/ferrosmart/8-other.added.md"
  stub_git add -A
  stub_git commit -q -m "the stub"

  expect "a package that is none" 2 --assemble ferrohealth-nope 0.0.2 2026-10-10
  expect "a version that is no version" 1 --assemble ferrohealth-authz 0.0 2026-10-10
  expect "a date that is no date" 1 --assemble ferrohealth-authz 0.0.2 10-10-2026
  expect "a missing argument" 2 --assemble ferrohealth-authz 0.0.2
  expect "an existing version" 1 --assemble ferrohealth-authz 0.0.1 2026-10-10
  expect "the cut" 0 --assemble ferrohealth-authz 0.0.2 2026-10-10

  cat > "$work/want" <<'EOF'
# Changelog

## [Unreleased]

## [0.0.2] - 2026-10-10

### Added

- An entry written into the changelog
  before the fragments.
- A second entry written into the changelog.
- Fragment 12-b (#12).
- Fragment 12-b names another issue (#99) and its own (#12) already.
- An entry that runs
  over two lines (#3).
  - and nests a list item.
- A second entry of fragment 3, unpunctuated (#3)

### Changed

- Fragment 7-y, beside FerroHEALTH/FerroEHR#7 (#7).

### Fixed

- A fix written into the changelog.

### Security

- Fragment 5-x (#5).

## [0.0.1] - 2026-10-01

### Added

- The first release.

[Unreleased]: https://example.org/r/compare/ferrohealth-authz-v0.0.2...HEAD
[0.0.2]: https://example.org/r/compare/ferrohealth-authz-v0.0.1...ferrohealth-authz-v0.0.2
[0.0.1]: https://example.org/r/releases/tag/ferrohealth-authz-v0.0.1
EOF
  diff -u "$work/want" "$log" > "$work/out" || flunk "the assembled changelog differs from the expected one."
  if [[ -n "$(stub_git ls-files -- "$FRAGMENT_DIR/ferrohealth-authz")" ]]; then
    flunk "a fragment is still tracked after the cut."
  fi
  [[ -f "$work/$FRAGMENT_DIR/ferrosmart/8-other.added.md" ]] || flunk "the cut removed another package's fragment."
  [[ -f "$work/$FRAGMENT_DIR/README.md" ]] || flunk "the cut removed the README."
  expect "a check after the cut" 0 --check

  # A second cut with nothing to release, and an [Unreleased] the cut cannot
  # read, are refused with the changelog untouched.
  stub_git commit -q -a -m "the cut"
  expect "a release with no entry" 1 --assemble ferrohealth-authz 0.0.3 2026-10-11
  grep -q 'would be empty' "$work/out" || flunk "the empty release was not named."
  printf '%s\n' '# Changelog' '' '## [Unreleased]' '' '### Improved' '' "$entry" '' \
    '[Unreleased]: https://example.org/r/compare/ferrohealth-authz-v0.0.2...HEAD' > "$log"
  cp "$log" "$work/before"
  expect "a section Keep a Changelog does not define" 1 --assemble ferrohealth-authz 0.0.3 2026-10-11
  cmp -s "$work/before" "$log" || flunk "a refused cut wrote the changelog."
  printf '%s\n' '# Changelog' '' '## [Unreleased]' '' 'Loose prose.' '' '### Added' '' "$entry" '' \
    '[Unreleased]: https://example.org/r/compare/ferrohealth-authz-v0.0.2...HEAD' > "$log"
  expect "text outside a section heading" 1 --assemble ferrohealth-authz 0.0.3 2026-10-11
  printf '%s\n' '# Changelog' '' '## [Unreleased]' '' '### Added' '' "$entry" > "$log"
  expect "no [Unreleased] link reference" 1 --assemble ferrohealth-authz 0.0.3 2026-10-11

  # A pending section a breaking change opened: its version's cut dates it
  # with its entries, [Unreleased]'s and the fragments; another version's cut
  # is refused.
  cat > "$log" <<'EOF'
# Changelog

## [Unreleased]

## [0.1.0] - Unreleased

### Changed

- Breaking: an entry of the pending section.

## [0.0.2] - 2026-10-10

### Added

- The second release.

[Unreleased]: https://example.org/r/compare/ferrohealth-authz-v0.0.2...HEAD
[0.0.2]: https://example.org/r/releases/tag/ferrohealth-authz-v0.0.2
EOF
  fragment 30-p.changed.md '- A fragment beside the pending section.'
  stub_git add -A
  stub_git commit -q -m "the pending section"
  expect "a cut of another version than the pending one" 1 --assemble ferrohealth-authz 0.0.3 2026-10-12
  grep -q 'pending section \[0.1.0\]' "$work/out" || flunk "the pending section was not named."
  expect "the cut of the pending version" 0 --assemble ferrohealth-authz 0.1.0 2026-10-12
  cat > "$work/want" <<'EOF'
# Changelog

## [Unreleased]

## [0.1.0] - 2026-10-12

### Changed

- Breaking: an entry of the pending section.
- A fragment beside the pending section (#30).

## [0.0.2] - 2026-10-10

### Added

- The second release.

[Unreleased]: https://example.org/r/compare/ferrohealth-authz-v0.1.0...HEAD
[0.1.0]: https://example.org/r/compare/ferrohealth-authz-v0.0.2...ferrohealth-authz-v0.1.0
[0.0.2]: https://example.org/r/releases/tag/ferrohealth-authz-v0.0.2
EOF
  diff -u "$work/want" "$log" > "$work/out" || flunk "the cut of the pending section differs from the expected one."
  stub_git commit -q -a -m "the pending cut"

  # The reason fragment: its form, its uniqueness per package, and its place
  # first under "### Security" in the preview and at the cut.
  cat > "$log" <<'EOF'
# Changelog

## [Unreleased]

## [0.1.0] - 2026-10-12

### Added

- The third release.

[Unreleased]: https://example.org/r/compare/ferrohealth-authz-v0.1.0...HEAD
[0.1.0]: https://example.org/r/releases/tag/ferrohealth-authz-v0.1.0
EOF
  fragment 20-reason.security-reason.md 'An entry that runs'
  expect "a reason without its prefix" 1 --check
  grep -q 'is not a reason paragraph' "$work/out" || flunk "the reason without its prefix was not named."
  fragment 20-reason.security-reason.md "$REASON_PREFIX"
  expect "a reason with nothing after its prefix" 1 --check
  fragment 20-reason.security-reason.md "${REASON_PREFIX}one." '- an entry'
  expect "a reason holding a list item" 1 --check
  fragment 20-reason.security-reason.md "${REASON_PREFIX}the fix needs" 'the console rewrite.'
  fragment 21-other.security-reason.md "${REASON_PREFIX}a second reason."
  expect "two reasons in one package" 1 --check
  grep -q 'merge them' "$work/out" || flunk "the second reason was not named."
  unfragment 21-other.security-reason.md
  expect "a reason for a Security section with no entry" 1 --preview ferrohealth-authz
  fragment 22-dep.security.md '- A dependency bump (GHSA-abcd-2345-wxyz).'
  fragment 23-feature.added.md '- A feature.'
  expect "the preview" 0 --preview ferrohealth-authz
  cat > "$work/want" <<EOF
# Changelog

## [Unreleased]

### Added

- A feature (#23).

### Security

${REASON_PREFIX}the fix needs
the console rewrite.

- A dependency bump (GHSA-abcd-2345-wxyz) (#22).

## [0.1.0] - 2026-10-12

### Added

- The third release.

[Unreleased]: https://example.org/r/compare/ferrohealth-authz-v0.1.0...HEAD
[0.1.0]: https://example.org/r/releases/tag/ferrohealth-authz-v0.1.0
EOF
  diff -u "$work/want" "$work/out" > "$work/diff" || { cp "$work/diff" "$work/out"; flunk "the preview differs from the expected one."; }
  [[ -f "$frag/22-dep.security.md" ]] || flunk "the preview removed a fragment."
  expect "the preview's release checks with a reason and a GHSA id" 0 --check-preview
  unfragment 20-reason.security-reason.md
  expect "the preview's release checks without the reason" 1 --check-preview
  grep -q 'does not open with' "$work/out" || flunk "the missing reason was not named."
  fragment 20-reason.security-reason.md "${REASON_PREFIX}the fix needs" 'the console rewrite.'
  fragment 22-dep.security.md '- A dependency bump with no advisory.'
  expect "the preview's release checks with an entry naming no advisory" 1 --check-preview
  grep -q 'names no GHSA id' "$work/out" || flunk "the entry without an advisory was not named."
  fragment 22-dep.security.md '- A dependency bump (GHSA-abcd-2345-wxyz).'
  stub_git add -A
  stub_git commit -q -m "the reason"
  expect "the cut with a reason" 0 --assemble ferrohealth-authz 0.2.0 2026-10-13
  awk '/^### Security/ { getline; getline; print; exit }' "$log" > "$work/out"
  grep -qF "${REASON_PREFIX}the fix needs" "$work/out" || flunk "the cut did not open the Security section with the reason."
  [[ ! -e "$frag/20-reason.security-reason.md" ]] || flunk "the cut left the reason fragment behind."

  echo "changelog: self-test passed."
}

case "${1:-}" in
--self-test)
  [[ $# -eq 1 ]] || usage
  self_test
  ;;
--check)
  [[ $# -eq 1 ]] || usage
  cd "$(dirname "$0")/../.."
  check
  ;;
--assemble)
  [[ $# -eq 4 ]] || usage
  known_package "$2"
  cd "$(dirname "$0")/../.."
  assemble "$2" "$3" "$4"
  ;;
--preview)
  [[ $# -eq 2 ]] || usage
  known_package "$2"
  cd "$(dirname "$0")/../.."
  assemble "$2" "" "" preview
  ;;
--check-preview)
  [[ $# -eq 1 ]] || usage
  cd "$(dirname "$0")/../.."
  check_preview
  ;;
*) usage ;;
esac
