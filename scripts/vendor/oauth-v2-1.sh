#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/oauth-v2-1.sh
#
# Vendors the OAuth 2.1 Authorization Framework Internet-Draft into
# docs/specs/oauth-v2-1/, the consolidation of RFC 6749, RFC 6750 and the
# security best current practice that the FerroSMART design cites beside
# them (#513). A draft revision is immutable once posted, so it is pinned by
# its versioned URL in the IETF archive and the sha256 of its text
# (scripts/vendor/lib/pinned.sh). The draft is subject to BCP 78 and the
# IETF Trust Legal Provisions, which permit copying it unmodified, as for
# the RFCs.
#
# Usage:
#   scripts/vendor/oauth-v2-1.sh           fetch and write the tree
#   scripts/vendor/oauth-v2-1.sh --check   check the committed tree, offline
#
# Requires: curl, shasum, awk.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "${1:-}" in
  --check) export PINNED_CHECK=1 ;;
  '') ;;
  *)
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"
# shellcheck source=scripts/vendor/lib/pinned.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/pinned.sh"

corpus_require curl shasum awk
pinned_begin

ietf='BCP 78 and the IETF Trust Legal Provisions (https://trustee.ietf.org/license-info): "Copyright (c) 2026 IETF Trust and the persons identified as the document authors. All rights reserved."; the Legal Provisions permit copying and distributing the document unmodified'

pin commit draft-ietf-oauth-v2-1-17.txt "draft-ietf-oauth-v2-1-17 (2026-10-31)" \
  https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-17.txt \
  5762f86fef656f4d5afd1d2fbd3bb79cbd25bbcba8c856dc7e0ad4851437b2a7 "$ietf" \
  'The OAuth 2.1 Authorization Framework, an Internet-Draft of the OAuth Working Group that would obsolete RFC 6749 and RFC 6750; a work in progress, cited beside the RFCs it consolidates and never in their place.'
pinned_corpus oauth-v2-1 "OAuth 2.1 Authorization Framework draft" \
  "the OAuth 2.1 Authorization Framework draft" \
  "Revision 17 of the OAuth 2.1 Authorization Framework Internet-Draft
(draft-ietf-oauth-v2-1), as the IETF archive serves it. An Internet-Draft is
a work in progress: the design cites it beside RFC 6749, RFC 6750 and
RFC 9700, which stay the normative ground." "" \
  "the FerroSMART requirements checklist (#513, \`docs/architecture.md\` §13)"

say "done"
