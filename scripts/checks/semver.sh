#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
#
# The patch-compatibility check of the three published crates
# (.claude/rules/crates-publishing.md): cargo-semver-checks compares the
# public API of each crate against its newest release on crates.io and
# refuses a break that the version in the manifest does not answer with a
# minor bump (0.x.y to 0.(x+1).0), the Cargo SemVer rules of
# https://doc.rust-lang.org/cargo/reference/semver.html. A public dependency
# (scripts/checks/lib/public-deps.sh) moved to another compatibility line
# breaks the crate where the judge cannot see it, so it needs the minor too
# (#426). It is what makes a caret requirement on these crates safe for the
# other family shared crates (no specification governs where the check runs:
# our own design). CI runs it on every pull request and in the merge queue
# over the workspace, and the release plan over the crate a tag releases.
#
# The judge runs two passes and fails when either fails: the default feature
# selection, and --only-explicit-features (no default features), which is
# what a dependent built with default-features = false compiles against, so
# moving a public item behind a default feature is a break there.
#
#   semver.sh [<crate>...]   judge the named crates, or every crate
#   semver.sh --changed <base>
#                            judge every crate when the change from <base> to
#                            HEAD reaches a crate, and nothing otherwise
#   semver.sh --pin          print the cargo-semver-checks version pinned in
#                            docs/VERSIONS.md, which CI installs
#
# A change that reaches no crate leaves every public API as it is on its
# base, so judging it would only judge the base: a pull request opened
# before a release and checked after it would be refused for the release's
# own changes. A change reaches the crates when it touches crates/, the
# workspace manifest or lock, the toolchain, the pin or this check; it then
# judges every crate, since one crate's change can reach another's API
# through a re-export. An unchanged version is judged as a patch. A crate
# with no release on crates.io is named and left out.
#
# The installed cargo-semver-checks must be the pinned version. Exit 1 when
# a crate breaks its API without the bump, 2 on a usage or setup error, when
# the judge could not build a crate, or while another run builds the
# baselines in target/semver/.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"

# The Pin cell of the cargo-semver-checks row, its backticks stripped.
pin="$(awk -F'|' '$2 ~ /^ *cargo-semver-checks *$/ { v = $3; gsub(/[^0-9.]/, "", v); print v; exit }' \
  "$root/docs/VERSIONS.md")"
if [[ -z "$pin" ]]; then
  echo "semver: docs/VERSIONS.md pins no cargo-semver-checks version" >&2
  exit 2
fi
if [[ "${1:-}" == "--pin" ]]; then
  [[ "$#" -eq 1 ]] || { echo "usage: semver.sh [<crate>...] | --pin" >&2; exit 2; }
  echo "$pin"
  exit 0
fi

if ! installed="$(cargo semver-checks --version 2>/dev/null)"; then
  echo "semver: cargo-semver-checks is not installed; install $pin (cargo binstall cargo-semver-checks@$pin)" >&2
  exit 2
fi
if [[ "$installed" != "cargo-semver-checks $pin" ]]; then
  echo "semver: found '$installed', docs/VERSIONS.md pins $pin" >&2
  exit 2
fi

if [[ "${1:-}" == "--changed" ]]; then
  [[ "$#" -eq 2 ]] || { echo "usage: semver.sh --changed <base>" >&2; exit 2; }
  if ! changed="$(git -C "$root" diff --name-only "$2" HEAD)"; then
    echo "semver: cannot compare $2 with HEAD" >&2
    exit 2
  fi
  if ! grep -qE '^(crates/|Cargo\.toml$|Cargo\.lock$|rust-toolchain\.toml$|docs/VERSIONS\.md$|scripts/checks/semver\.sh$|scripts/checks/lib/public-deps\.sh$)' <<<"$changed"; then
    echo "semver: the change from $2 reaches no crate; every public API is its base's"
    exit 0
  fi
  set --
fi
cd "$root"
# shellcheck source=scripts/checks/lib/public-deps.sh
. scripts/checks/lib/public-deps.sh

crates=("$@")
if [[ "${#crates[@]}" -eq 0 ]]; then
  for manifest in crates/*/Cargo.toml; do
    crates+=("$(basename "$(dirname "$manifest")")")
  done
fi
for crate in "${crates[@]}"; do
  [[ -f "crates/$crate/Cargo.toml" ]] || { echo "semver: no crate crates/$crate" >&2; exit 2; }
done

# The baselines build in a target directory of their own (#265), so no other
# cargo run of this checkout reads or writes them while they build, and one
# run at a time holds it: a second run is told so, never left to fail inside
# a half-built baseline (no specification governs this: our own design).
export CARGO_TARGET_DIR="$root/target/semver"
mkdir -p "$CARGO_TARGET_DIR"
lock="$CARGO_TARGET_DIR/.lock"
if ! mkdir "$lock" 2>/dev/null; then
  holder="$(cat "$lock/pid" 2>/dev/null || true)"
  if [[ "$holder" =~ ^[0-9]+$ ]] && kill -0 "$holder" 2>/dev/null; then
    echo "semver: another run (pid $holder) is building the baselines in $CARGO_TARGET_DIR; run again when it ends" >&2
    exit 2
  fi
  echo "semver: taking over $lock, left by a run that is gone" >&2
  rm -rf "$lock"
  mkdir "$lock"
fi
echo "$$" >"$lock/pid"
trap 'rm -rf "$lock"' EXIT

# The `version` of the `[package]` table of crate $1, or the workspace
# version when the crate inherits it.
crate_version() {
  local own
  own="$(awk -F'"' '/^\[package\]/{p=1; next} /^\[/{p=0} p && /^version[[:space:]]*=/{print $2; exit}' "crates/$1/Cargo.toml")"
  if [[ -n "$own" ]]; then
    echo "$own"
  else
    awk -F'"' '/^\[workspace\.package\]/{p=1; next} /^\[/{p=0} p && /^version[[:space:]]*=/{print $2; exit}' Cargo.toml
  fi
}

# The crates.io API document at path $1 under /api/v1/crates/, into the
# variable `document`; returns 1 when crates.io knows no such path and exits
# 2 when it cannot be read.
crates_io() {
  local answer code
  if ! answer="$(curl --proto '=https' --tlsv1.2 -sSL -w '\n%{http_code}' \
    -H 'User-Agent: ferrohealth-semver (scripts/checks/semver.sh)' \
    "https://crates.io/api/v1/crates/$1")"; then
    echo "semver: crates.io could not be reached for $1" >&2
    exit 2
  fi
  code="${answer##*$'\n'}"
  document="${answer%$'\n'*}"
  case "$code" in
    200) return 0 ;;
    404) return 1 ;;
    *)
      echo "semver: crates.io answered $code for $1" >&2
      exit 2
      ;;
  esac
}

# Whether versions $1 and $2 share their compatibility line: the major, and
# the minor too while the major is 0 (the Cargo caret rule).
same_line() {
  [[ "$(compat_line "$1")" == "$(compat_line "$2")" ]]
}

log="$CARGO_TARGET_DIR/.lock/log"
broke=""
unjudged=""
for crate in "${crates[@]}"; do
  current="$(crate_version "$crate")"
  previous=""
  if crates_io "$crate"; then
    previous="$(jq -r '.crate.max_stable_version // empty' <<<"$document")"
  fi
  if [[ -z "$previous" ]] || [[ "$previous" == "0.0.0" ]]; then
    echo "semver: $crate has no release on crates.io to compare with; it is not judged"
    continue
  fi
  echo "semver: $crate $previous -> $current against crates.io" >&2
  for pass in default explicit; do
    args=(check-release --package "$crate")
    [[ "$pass" == default ]] || args+=(--only-explicit-features)
    echo "semver: $crate, the $pass feature selection" >&2
    status=0
    cargo semver-checks "${args[@]}" >"$log" 2>&1 || status=$?
    cat "$log"
    # Only a summary the judge printed counts as a judgement; a build that
    # fails is named apart from a break.
    if [[ "$status" -ne 0 ]] && grep -q 'semver requires new' "$log"; then
      echo "::error::semver: $crate $current breaks its public API against $previous ($pass features); a breaking change bumps the minor while the crate is 0.x (.claude/rules/crates-publishing.md)." >&2
      broke="$broke $crate"
    elif [[ "$status" -ne 0 ]] || ! grep -q 'Summary' "$log"; then
      echo "::error::semver: cargo-semver-checks could not judge $crate $current against $previous ($pass features, exit $status); see its output above." >&2
      unjudged="$unjudged $crate"
    fi
  done
  # A public dependency on another line breaks the crate where the judge
  # cannot see it (#426): it needs the minor.
  if ! crates_io "$crate/$previous/dependencies"; then
    echo "semver: crates.io lists no dependencies of $crate $previous" >&2
    exit 2
  fi
  released="$(jq -r '.dependencies[] | select(.kind == "normal") | "\(.crate_id) \(.req)"' <<<"$document" | public_lines)"
  moved="$(moved_lines "$released" "$(manifest_requirements Cargo.toml "crates/$crate/Cargo.toml" | public_lines)")"
  if [[ -n "$moved" ]]; then
    if same_line "$previous" "$current"; then
      echo "::error::semver: $crate $current stays on the line of $previous while a public dependency moves to another compatibility line ($moved); that breaks its consumers, so it bumps the minor (.claude/rules/crates-publishing.md)." >&2
      broke="$broke $crate"
    else
      echo "semver: $crate leaves its line for its public dependencies ($moved)"
    fi
  fi
done

if [[ -n "$unjudged" ]]; then
  echo "semver: the judge could not build:$unjudged" >&2
  exit 2
fi
if [[ -n "$broke" ]]; then
  echo "semver: refused:$broke" >&2
  exit 1
fi
echo "semver: every judged version answers its change"
