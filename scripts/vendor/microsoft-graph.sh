#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/microsoft-graph.sh
#
# Pins the Microsoft Graph v1.0 pages the `idp-entra` groups overage adapter
# of #221 cites: `directoryObject: getMemberObjects` (the request the adapter
# sends), `directoryObject: getMemberGroups` (its groups-only sibling and the
# result size limit), and "Microsoft Graph throttling guidance" (the `429`
# and its `Retry-After`), with the repository's two licence files, from
# microsoftgraph/microsoft-graph-docs-contrib at the commit each URL names.
# Each artefact is pinned by its URL and the sha256 of its bytes
# (scripts/vendor/lib/pinned.sh), and the "Microsoft Graph documentation"
# row of docs/VERSIONS.md carries the pin-set digest.
#
# Redistribution: the repository's `LICENSE` holds the Creative Commons
# Attribution 4.0 International text, while its `LICENSE.md` states that the
# repository "is licensed under the Creative Commons
# Attribution-NonCommercial-NoDerivs 3.0 United States" licence. The two
# disagree and the second allows no commercial use, so every page is cache
# only: fetched into the git-ignored .vendor-cache/microsoft-graph/ and never
# committed. The script writes only docs/specs/microsoft-graph/PROVENANCE.md
# into the tree.
#
# Usage:
#   scripts/vendor/microsoft-graph.sh
#
# Requires: curl, shasum, awk.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"
# shellcheck source=scripts/vendor/lib/pinned.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/pinned.sh"

corpus_require curl shasum awk
pinned_begin

commit="bb35043c742d4406d73ccae904c05fbfca7c7428"
raw="https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-docs-contrib/$commit"
version="microsoftgraph/microsoft-graph-docs-contrib commit $commit (the default branch head on 2026-11-05)"
licence='LICENSE.md: "This repository is licensed under the Creative Commons Attribution-NonCommercial-NoDerivs 3.0 United States license"; LICENSE: the Creative Commons Attribution 4.0 International text. The two disagree, and the first allows no commercial use'

pin cache directoryobject-getmemberobjects.md "$version" \
  "$raw/api-reference/v1.0/api/directoryobject-getmemberobjects.md" \
  622c6b4a6ca95b56ab2438a73a3f5b392bdcdc721afbfd70b2010e8b4c70046c "$licence" \
  "POST /users/{id}/getMemberObjects and /servicePrincipals/{id}/getMemberObjects, the securityEnabledOnly body parameter, and 200 OK with a String collection in value"
pin cache directoryobject-getmembergroups.md "$version" \
  "$raw/api-reference/v1.0/api/directoryobject-getmembergroups.md" \
  ec0107c0cb682da9562b5d034d904d5d7dd6b6d161139a86fedacdbc0913cb15 "$licence" \
  "The groups-only sibling, which returns up to 11,000 group IDs and answers 400 Directory_ResultSizeLimitExceeded above it"
pin cache throttling.md "$version" \
  "$raw/concepts/throttling.md" \
  bcf59f10c6daad493751931665811baab232eb9be8e8aa201ae3f72233068e42 "$licence" \
  "A throttled request answers 429 Too Many Requests with a Retry-After header in seconds"
pin cache LICENSE.md "$version" \
  "$raw/LICENSE.md" \
  306890513ee0cfa57c1aae38fc54dad8c27860d0d5d63f400ceacf1b604eb9cd "$licence" \
  "The repository's licence statement"
pin cache LICENSE "$version" \
  "$raw/LICENSE" \
  7183ef9749eb9b75e710a81a4c812a9405cc184f087500581a973e5929ac3f5e "$licence" \
  "The Creative Commons Attribution 4.0 International text"
pinned_corpus microsoft-graph "Microsoft Graph documentation" \
  "the Microsoft Graph v1.0 reference pages" \
  "The Microsoft Graph v1.0 reference pages the \`idp-entra\` adapter reads a
person's group memberships through, from
<https://github.com/microsoftgraph/microsoft-graph-docs-contrib>, rendered
under <https://learn.microsoft.com/graph>. The repository's \`LICENSE.md\`
states the Creative Commons Attribution-NonCommercial-NoDerivs 3.0 United
States licence and its \`LICENSE\` holds the Creative Commons Attribution 4.0
International text. The statements disagree and the first allows no
commercial use, so every page is cache only and this repository carries none
of its content.

Examined and not taken: \`user-list-memberof.md\`, the paged listing of
directory objects, which the adapter does not call." \
  "" \
  "the \`idp-entra\` groups overage adapter of #221"

say "done"
