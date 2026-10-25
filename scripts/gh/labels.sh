#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/gh/labels.sh: bootstrap the FerroAUTH issue-label taxonomy.
#
# Creates, idempotently, the WORK-KIND labels a Task carries to pick its
# commit type (a Bug and a Feature carry none: the native issue type says fix
# or feat), the DOMAIN labels, and the workflow labels. The type, priority
# and effort of an issue are GitHub's native issue type and the
# organisation's issue fields (scripts/gh/fields.sh), never labels, so the
# six labels that once carried them are deleted where they exist.
#
# `gh label create --force` updates an existing label in place, so a re-run
# converges colours and descriptions. No specification governs the taxonomy:
# our own design. https://cli.github.com/manual/gh_label_create
#
# Usage: scripts/gh/labels.sh
set -euo pipefail

die() {
  echo "gh-labels: $*" >&2
  exit 1
}

[[ "$#" -eq 0 ]] || {
  echo "usage: scripts/gh/labels.sh" >&2
  exit 2
}

command -v gh > /dev/null 2>&1 || die "the GitHub CLI (gh) is not installed"
gh repo view --json nameWithOwner --jq .nameWithOwner > /dev/null 2>&1 ||
  die "could not resolve the current repository (run inside a gh-authenticated clone)"

EXISTING="$(gh label list --limit 200 --json name --jq '.[].name')"

# label <name> <hex-color> <description>
label() {
  gh label create "$1" --color "$2" --description "$3" --force > /dev/null
  echo "ok: $1"
}

# retire <name>: delete a label the taxonomy no longer carries, if it exists.
retire() {
  if grep -qx -- "$1" <<< "$EXISTING"; then
    gh label delete "$1" --yes > /dev/null
    echo "retired: $1"
  fi
  return 0
}

echo "== retired labels (the native issue type and the fields carry these) =="
for name in bug enhancement P0 P1 P2 P3 accessibility component theming gallery; do retire "$name"; done

echo "== work-kind labels (on a Task only) =="
label documentation 0075ca "Docs-only work. Maps to a docs/ branch and a docs: commit."
label chore fef2c0 "Maintenance with no product change. chore/ and chore:."
label refactor cfd3d7 "Behaviour-preserving code change. refactor/ and refactor:."
label perf fbca04 "Performance or bundle-size work. perf/ and perf:."
label test c2e0c6 "Test-only work. test/ and test:."
label ci ededed "CI, build, and tooling. ci/ and ci:."

echo "== domain labels =="
label resource-server 1d76db "Token validation, issuer discovery and the key set."
label scopes 5319e7 "SMART scopes and the patient compartment."
label machine-auth 0e8a16 "HTTP Basic and the client credentials grant."
label audit 006b75 "The audit line."
label "spec:SMART" fbca04 "SMART App Launch, the specification."
label "spec:OAuth" d93f0b "The OAuth 2.0, JWT and Basic RFCs and OpenID Connect Discovery."

echo "== workflow labels =="
label dependencies 0366d6 "Dependency updates (used by Dependabot)."
label security ee0701 "Security fix or hardening."
label blocked-upstream 6f42c1 "Waiting on an upstream specification or tool release."
label no-changelog bfdadc "PR escape hatch: the change has no effect a product sees."

echo "done."
