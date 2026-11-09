#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
#
# The patch-compatibility check: cargo-semver-checks compares the public API
# of each crate against its newest version on crates.io and refuses a break
# that the version in the manifest does not answer with a minor bump
# (0.x.y to 0.(x+1).0), the Cargo SemVer rules of
# https://doc.rust-lang.org/cargo/reference/semver.html. It is what makes a
# caret requirement on these crates safe for the other family shared crates
# (no specification governs where the check runs: our own design). CI runs it
# on every pull request over the workspace, and the release plan over the
# crate a tag releases.
#
# It runs two passes and fails when either fails: the default feature
# selection, and --only-explicit-features (no default features), which is
# what a dependent built with default-features = false compiles against, so
# moving a public item behind a default feature is a break there.
#
#   semver.sh [<crate>...]   check the named crates, or every crate
#   semver.sh --changed <base>
#                            check every crate when the change from <base> to
#                            HEAD reaches a crate, and nothing otherwise
#   semver.sh --pin          print the cargo-semver-checks version pinned in
#                            docs/VERSIONS.md, which CI installs
#
# A change that reaches no crate leaves every public API as it is on its
# base, so judging it would only judge the base: a pull request opened
# before a release and checked after it would be refused for the release's
# own changes. A change reaches the crates when it touches crates/, the
# workspace manifest or lock, the toolchain, the pin or this check; it then
# checks every crate, since one crate's change can reach another's API
# through a re-export.
#
# The installed cargo-semver-checks must be the pinned version. Exit 1 when
# a crate breaks its API without the bump, 2 on a usage or setup error or
# while another run builds the baselines in target/semver/.
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

args=()
if [[ "${1:-}" == "--changed" ]]; then
  [[ "$#" -eq 2 ]] || { echo "usage: semver.sh --changed <base>" >&2; exit 2; }
  if ! changed="$(git -C "$root" diff --name-only "$2" HEAD)"; then
    echo "semver: cannot compare $2 with HEAD" >&2
    exit 2
  fi
  if ! grep -qE '^(crates/|Cargo\.toml$|Cargo\.lock$|rust-toolchain\.toml$|docs/VERSIONS\.md$|scripts/checks/semver\.sh$)' <<<"$changed"; then
    echo "semver: the change from $2 reaches no crate; every public API is its base's"
    exit 0
  fi
  set --
fi
if [[ "$#" -eq 0 ]]; then
  args=(--workspace)
else
  for crate in "$@"; do args+=(--package "$crate"); done
fi
cd "$root"

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

# The higher exit code of the two passes wins, so a setup error stays 2.
status=0
echo "semver: pass 1 of 2, the default feature selection" >&2
cargo semver-checks check-release "${args[@]}" || status=$?
echo "semver: pass 2 of 2, no default features (--only-explicit-features)" >&2
cargo semver-checks check-release --only-explicit-features "${args[@]}" || {
  code=$?
  if (( code > status )); then status=$code; fi
}
exit "$status"
