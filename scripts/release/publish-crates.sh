#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The crates.io upload of the published members, and its read-back, as one
# implementation shared by the `crates` leg of release.yml (a `v*` tag,
# approval-gated) and publish-crates.yml (a manual dispatch: the dry-run and
# recovery lane). The two lanes cannot share a reusable workflow: crates.io
# Trusted Publishing matches the OIDC `workflow_ref` claim, and for a job
# inside a reusable workflow that claim names the calling workflow
# (<https://crates.io/docs/trusted-publishing>), so the shared thing is this
# script and each lane keeps its own job and identity.
#
# One crate at a time, "already exists" counted as done, makes the lane
# resumable and idempotent; the registry is read back before success is
# reported (no specification governs this: our own design).
#
# Usage:
#   publish-crates.sh publish          # upload each crate in order
#   publish-crates.sh verify           # read the registry back, with retries
#   publish-crates.sh version [CRATE]  # print one crate's version
#   publish-crates.sh guard            # refuse unless run at the release tag
#   publish-crates.sh --self-test      # prove `guard` against a stub gh
#
# `guard` is the manual lane's precondition: the run's ref is the tag
# v<manifest version> (GITHUB_REF_TYPE, GITHUB_REF_NAME) and a published
# GitHub release exists for it, read with gh in GITHUB_REPOSITORY, so the
# manual lane recovers a release and never makes one.
#
# Requires cargo, curl, and jq; `publish` also needs CARGO_REGISTRY_TOKEN, and
# `guard` needs gh with GH_TOKEN.
set -euo pipefail
cd "$(dirname "$0")/../.."

# The published members, in dependency order.
readonly CRATES=(
  ferrohealth-smart
)

# The version cargo resolves for one member: its own, or the workspace's when
# it inherits it.
manifest_version() {
  cargo metadata --format-version 1 --no-deps --locked |
    jq -r --arg name "$1" '.packages[] | select(.name == $name) | .version'
}

# cargo colours the status word, so "Uploaded" is followed by a reset sequence
# before the crate name; strip the colour before matching.
readonly ESC=$'\033'
strip_ansi() {
  sed -E "s/${ESC}\\[[0-9;]*m//g"
}

do_publish() {
  local crate out plain failed=""
  for crate in "${CRATES[@]}"; do
    echo "::group::$crate $(manifest_version "$crate")"
    out="$(cargo publish -p "$crate" --locked 2>&1)" || true
    printf '%s\n' "$out"
    echo "::endgroup::"
    plain="$(printf '%s' "$out" | strip_ansi)"
    case "$plain" in
      *"already exists on crates.io index"* | *"already uploaded"*)
        echo "$crate: already published at this version, nothing to do"
        ;;
      *)
        if printf '%s' "$plain" | grep -q "Uploaded $crate"; then
          echo "$crate: uploaded"
        else
          failed="$failed $crate"
        fi
        ;;
    esac
  done
  [[ -z "$failed" ]] || {
    echo "::error::failed to publish:$failed"
    return 1
  }
  echo "publish-crates: every crate is at its version or was already there"
}

# Read the registry, never the exit code alone. The index is eventually
# consistent right after an upload: a miss is retried, and a failed request
# counts as "not seen yet", not as a miss.
do_verify() {
  local crate want got body bad=""
  for crate in "${CRATES[@]}"; do
    want="$(manifest_version "$crate")"
    got=""
    for _ in 1 2 3 4 5 6; do
      if body="$(curl --proto '=https' --tlsv1.2 -sSL --fail \
        -H 'User-Agent: ferrohealth-smart-publish-verify (scripts/release/publish-crates.sh)' \
        "https://crates.io/api/v1/crates/$crate/versions" 2> /dev/null)"; then
        got="$(printf '%s' "$body" |
          jq -r --arg v "$want" '.versions[]? | select(.num == $v) | .num' |
          head -1)" || got=""
      fi
      [[ -n "$got" ]] && break
      sleep 10
    done
    printf '%-22s want %-10s %s\n' "$crate" "$want" "${got:-MISSING}"
    [[ -n "$got" ]] || bad="$bad $crate@$want"
  done
  [[ -z "$bad" ]] || {
    echo "::error::the published set is incomplete:$bad"
    return 1
  }
  echo "publish-crates: confirmed on crates.io, all ${#CRATES[@]} crates at their versions"
}

# do_guard REF_TYPE REF_NAME VERSION: refuses, naming what is missing, unless
# the ref is the tag vVERSION and a published release exists for that tag.
do_guard() {
  local ref_type="$1" ref_name="$2" version="$3" tag draft
  tag="v$version"
  if [[ "$ref_type" != "tag" ]]; then
    echo "::error::publish-crates: the run is at the $ref_type '$ref_name', not the tag $tag; dispatch it at the tag" >&2
    return 1
  fi
  if [[ "$ref_name" != "$tag" ]]; then
    echo "::error::publish-crates: the run is at the tag '$ref_name', but the manifest names $version, whose tag is $tag" >&2
    return 1
  fi
  if ! draft="$(gh release view "$tag" --repo "${GITHUB_REPOSITORY:?}" --json isDraft --jq .isDraft 2> /dev/null)"; then
    echo "::error::publish-crates: no GitHub release exists for the tag $tag" >&2
    return 1
  fi
  if [[ "$draft" != "false" ]]; then
    echo "::error::publish-crates: the GitHub release of the tag $tag is a draft, not published" >&2
    return 1
  fi
  echo "publish-crates: the run is at the tag $tag, which has a published release"
}

self_test() {
  local fails=0 out rc
  export GITHUB_REPOSITORY=o/r
  # The stub answers the one call `guard` makes: v1.0.0 is released, v1.1.0
  # is a draft, and every other tag has no release.
  # shellcheck disable=SC2329 # do_guard calls it in place of gh
  gh() {
    case "$*" in
      "release view v1.0.0 --repo o/r --json isDraft --jq .isDraft") echo false ;;
      "release view v1.1.0 --repo o/r --json isDraft --jq .isDraft") echo true ;;
      "release view "*) return 1 ;;
      *)
        echo "stub gh: unexpected call: $*" >&2
        return 1
        ;;
    esac
  }
  # expect NAME WANT_RC WANT_TEXT -- ARGS...
  expect() {
    local name="$1" want_rc="$2" want_text="$3"
    shift 4
    if out="$(do_guard "$@" 2>&1)"; then rc=0; else rc=$?; fi
    if [[ "$rc" != "$want_rc" || "$out" != *"$want_text"* ]]; then
      echo "FAIL: $name (exit $rc): $out" >&2
      fails=$((fails + 1))
    fi
  }
  expect "the released tag passes" 0 "has a published release" -- tag v1.0.0 1.0.0
  expect "a branch is refused" 1 "not the tag v1.0.0" -- branch main 1.0.0
  expect "another tag is refused" 1 "whose tag is v1.0.0" -- tag v0.9.0 1.0.0
  expect "a tag without a release is refused" 1 "no GitHub release" -- tag v1.2.0 1.2.0
  expect "a draft release is refused" 1 "is a draft" -- tag v1.1.0 1.1.0
  unset -f gh
  if [[ "$fails" -ne 0 ]]; then
    echo "publish-crates: self-test FAILED ($fails)" >&2
    return 1
  fi
  echo "publish-crates: self-test OK."
}

case "${1:-}" in
  publish) do_publish ;;
  verify) do_verify ;;
  version) manifest_version "${2:-ferrohealth-smart}" ;;
  guard) do_guard "${GITHUB_REF_TYPE:?}" "${GITHUB_REF_NAME:?}" "$(manifest_version ferrohealth-smart)" ;;
  --self-test) self_test ;;
  *)
    echo "publish-crates: expected 'publish', 'verify', 'version', 'guard', or '--self-test', got '${1:-<none>}'" >&2
    exit 2
    ;;
esac
