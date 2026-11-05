#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/okta.sh
#
# Pins the Okta "OpenID Connect & OAuth 2.0 API" reference the `okta` issuer
# profile of #215 cites (the reserved claims of the access token: `uid`,
# `cid`), as Okta serves it on developer.okta.com. No file of the
# okta/okta-developer-docs repository is its source, so it is pinned by its URL
# and the sha256 of its bytes (scripts/vendor/lib/pinned.sh), and the "Okta
# OpenID Connect and OAuth 2.0 API" row of docs/VERSIONS.md carries the
# pin-set digest.
#
# Redistribution: the page reads "Copyright © 2026 Okta. All rights
# reserved.", and okta/okta-developer-docs declares no licence, so the page is
# cache only: fetched into the git-ignored .vendor-cache/okta/ and never
# committed. The script writes only docs/specs/okta/PROVENANCE.md into the
# tree. The page is rebuilt with each Okta deploy, so a re-run that finds
# other bytes fails and the pin is moved by hand after reading the change.
#
# Usage:
#   scripts/vendor/okta.sh
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

reserved='Copyright © 2026 Okta. All rights reserved. (the page footer and <https://developer.okta.com/copyright/>, which adds "See Okta'"'"'s Terms of Service for its Intellectual Property"); okta/okta-developer-docs carries no licence file and GitHub reports no licence for it'

pin cache okta-oauth-overview.html \
  "no version stated; the page as served on 2026-11-05" \
  "https://developer.okta.com/docs/api/openapi/okta-oauth/guides/overview/" \
  572ba6a714905712e698ccabf09fc25edfda704a0c66996fe793ef3385d29ff8 "$reserved" \
  "The reserved claims of the access token: uid (\"A unique identifier for the user\", absent when no user is bound to the token) and cid (\"Client ID of the client that requested the access token\")"
pinned_corpus okta "Okta OpenID Connect and OAuth 2.0 API" \
  "the Okta OpenID Connect and OAuth 2.0 API reference" \
  "The \"OpenID Connect & OAuth 2.0\" API reference of Okta's developer
documentation, the overview page that lists the claims of an Okta access
token. Okta states that the page is \"Copyright © 2026 Okta. All rights
reserved.\" and grants no licence to copy it, so it is cache only and this
repository carries none of its content.

Examined and not taken: the \`okta/okta-developer-docs\` repository, which
holds the guides of developer.okta.com and no source of this API reference
page, and which declares no licence." \
  "" \
  "the \`okta\` issuer profile of #215, vendored by #222"

say "done"
