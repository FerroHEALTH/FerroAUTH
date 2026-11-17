#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
#
# toolchain.sh: the pinned documentation toolchain, read from the
# "Documentation toolchain" table of docs/VERSIONS.md (no specification
# governs this: our own design).
#
#   . scripts/site/toolchain.sh     sets MDBOOK_VERSION, MDBOOK_LINT_VERSION
#                                   and LYCHEE_VERSION
#   scripts/site/toolchain.sh       prints the taiki-e/install-action list
#
# The pin matrix is the one place a version is written, so a bump is one row
# there. A row that is missing or empty fails loud, naming the row.

set -euo pipefail

_toolchain_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# toolchain_pin ITEM: the pin of the row ITEM of docs/VERSIONS.md.
toolchain_pin() {
  local item="$1" value
  value="$(awk -F'|' -v item="$item" '{ gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2) }
    $2 == item { v = $3; gsub(/[[:space:]`]/, "", v); print v; exit }' "$_toolchain_root/docs/VERSIONS.md")"
  if [[ -z "$value" ]]; then
    echo "toolchain: docs/VERSIONS.md has no pin for $item" >&2
    return 1
  fi
  printf '%s\n' "$value"
}

MDBOOK_VERSION="$(toolchain_pin mdBook)"
MDBOOK_LINT_VERSION="$(toolchain_pin mdbook-lint)"
LYCHEE_VERSION="$(toolchain_pin lychee)"
export MDBOOK_VERSION MDBOOK_LINT_VERSION LYCHEE_VERSION

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "mdbook@${MDBOOK_VERSION},mdbook-lint@${MDBOOK_LINT_VERSION},lychee@${LYCHEE_VERSION}"
fi
