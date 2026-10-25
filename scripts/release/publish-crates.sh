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
# Two crates publish from this workspace, each on its own version line and
# tag: ferrohealth-smart at `v<version>` and ferrohealth-authz at
# `ferrohealth-authz-v<version>`. A run publishes the one crate its tag
# releases.
#
# Usage:
#   publish-crates.sh publish CRATE    # upload one crate
#   publish-crates.sh verify CRATE     # read the registry back, with retries
#   publish-crates.sh version [CRATE]  # print one crate's version
#   publish-crates.sh crate TAG        # print the crate a release tag names
#   publish-crates.sh guard            # refuse unless run at the release tag
#   publish-crates.sh --self-test      # prove `guard` against a stub gh
#
# `guard` is the manual lane's precondition: the run's ref is the release
# tag of the crate it names, at that crate's manifest version
# (GITHUB_REF_TYPE, GITHUB_REF_NAME), and a published GitHub release exists
# for it, read with gh in GITHUB_REPOSITORY, so the manual lane recovers a
# release and never makes one; it prints the crate.
#
# Requires cargo, curl, and jq; `publish` also needs CARGO_REGISTRY_TOKEN, and
# `guard` needs gh with GH_TOKEN.
set -euo pipefail
cd "$(dirname "$0")/../.."

# The published members, in dependency order.
readonly CRATES=(
  ferrohealth-smart
  ferrohealth-authz
)

# The crate a release tag names.
crate_of_tag() {
  case "$1" in
    ferrohealth-authz-v*) echo ferrohealth-authz ;;
    v*) echo ferrohealth-smart ;;
    *) return 1 ;;
  esac
}

# The tag prefix of a crate's releases.
tag_prefix() {
  case "$1" in
    ferrohealth-authz) echo ferrohealth-authz-v ;;
    *) echo v ;;
  esac
}

# Refuses a name that is not a published member.
known_crate() {
  local crate
  for crate in "${CRATES[@]}"; do
    [[ "$crate" != "$1" ]] || return 0
  done
  echo "::error::publish-crates: '$1' is not a published member (${CRATES[*]})" >&2
  return 1
}

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
  for crate in "$@"; do
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
  for crate in "$@"; do
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
  echo "publish-crates: confirmed on crates.io, $* at the manifest version"
}

# do_guard REF_TYPE REF_NAME VERSION [PREFIX]: refuses, naming what is
# missing, unless the ref is the tag PREFIX VERSION (PREFIX `v` by default)
# and a published release exists for that tag.
do_guard() {
  local ref_type="$1" ref_name="$2" version="$3" prefix="${4:-v}" tag draft
  tag="$prefix$version"
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
  expect "an authz tag of another version is refused" 1 "whose tag is ferrohealth-authz-v0.2.0" -- tag ferrohealth-authz-v0.1.0 0.2.0 ferrohealth-authz-v
  if [[ "$(crate_of_tag ferrohealth-authz-v0.1.0)" != ferrohealth-authz || "$(crate_of_tag v0.7.0)" != ferrohealth-smart ]] || crate_of_tag main > /dev/null; then
    echo "FAIL: the crate of a tag" >&2
    fails=$((fails + 1))
  fi
  unset -f gh
  if [[ "$fails" -ne 0 ]]; then
    echo "publish-crates: self-test FAILED ($fails)" >&2
    return 1
  fi
  echo "publish-crates: self-test OK."
}

case "${1:-}" in
  publish | verify)
    [[ "$#" -eq 2 ]] || {
      echo "publish-crates: '$1' takes the crate to act on" >&2
      exit 2
    }
    known_crate "$2"
    if [[ "$1" == publish ]]; then do_publish "$2"; else do_verify "$2"; fi
    ;;
  version) manifest_version "${2:-ferrohealth-smart}" ;;
  crate)
    crate_of_tag "${2:-}" || {
      echo "::error::publish-crates: '${2:-}' is no release tag" >&2
      exit 2
    }
    ;;
  guard)
    crate="$(crate_of_tag "${GITHUB_REF_NAME:?}")" || {
      echo "::error::publish-crates: the run is at '${GITHUB_REF_NAME}', which is no release tag" >&2
      exit 1
    }
    do_guard "${GITHUB_REF_TYPE:?}" "$GITHUB_REF_NAME" "$(manifest_version "$crate")" "$(tag_prefix "$crate")" >&2
    echo "$crate"
    ;;
  --self-test) self_test ;;
  *)
    echo "publish-crates: expected 'publish', 'verify', 'version', 'crate', 'guard', or '--self-test', got '${1:-<none>}'" >&2
    exit 2
    ;;
esac
