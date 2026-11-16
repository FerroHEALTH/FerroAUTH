#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/okta.sh
#
# Pins the Okta "OpenID Connect & OAuth 2.0 API" reference the `okta` issuer
# profile of #215 cites (the reserved claims of the access token: `uid`,
# `cid`), and the reference pages and guides FerroSMART's Okta login setup
# cites (#525: client authentication, the custom authorization server's
# metadata, the authorization servers, the custom and groups claims, the
# authorization code grant), as Okta serves them on developer.okta.com. They
# are pinned by URL and the sha256 of their bytes
# (scripts/vendor/lib/pinned.sh), and the "Okta OpenID Connect and OAuth 2.0
# API" row of docs/VERSIONS.md carries the pin-set digest.
#
# Redistribution: every page reads "Copyright © 2026 Okta. All rights
# reserved.", and okta/okta-developer-docs declares no licence, so the pages
# are cache only: fetched into the git-ignored .vendor-cache/okta/ and never
# committed. The script writes only docs/specs/okta/PROVENANCE.md into the
# tree. The pages are rebuilt with Okta's deploys, so a re-run that finds
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

served='the page as served on 2026-11-16'
pin cache okta-oauth-overview.html \
  "no version stated; the page as served on 2026-11-16, last updated October 6, 2026, re-pinned after the bytes of the 2026-11-05 pin moved" \
  "https://developer.okta.com/docs/api/openapi/okta-oauth/guides/overview" \
  572ba6a714905712e698ccabf09fc25edfda704a0c66996fe793ef3385d29ff8 "$reserved" \
  "The reserved claims of the access token: uid (\"A unique identifier for the user\", absent when no user is bound to the token), cid (\"Client ID of the client that requested the access token\"), scp (\"Array of scopes\"), and a header whose only reserved claims are alg and kid; the ID token's base and scope-dependent claims (sub, iss, aud, groups with its limit of 100), alg always RS256"
pin cache okta-oauth-client-auth.html \
  "no version stated; $served, last updated October 16, 2026" \
  "https://developer.okta.com/docs/api/openapi/okta-oauth/guides/client-auth" \
  dd3af747e72aab0d0356b72e73e5b215d66aa2f45224357329d2e3e57caefcfc "$reserved" \
  "Client authentication methods: client_secret_basic is the default, the secret in the Authorization header as Basic"
pin cache okta-oauth-customas.html \
  "no version stated; $served" \
  "https://developer.okta.com/docs/api/openapi/okta-oauth/oauth/customas" \
  d7c3f759434ccae74dc223749ef9c61f10bd64a5012d533527cf9442220ab97a "$reserved" \
  "Custom Authorization Servers: the RFC 8414 metadata at /.well-known/oauth-authorization-server/oauth2/{authorizationServerId} and the OpenID Connect metadata, with their members"
pin cache okta-auth-servers.html \
  "no version stated; $served" \
  "https://developer.okta.com/docs/concepts/auth-servers/" \
  d185ad90b624f050d49e067f887058052ccdb7b2773d5c2c66c33356e9819773 "$reserved" \
  "Authorization servers: the org and custom authorization servers, their issuers and discovery endpoints, the default custom authorization server"
pin cache okta-customize-tokens.html \
  "no version stated; $served" \
  "https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/main/" \
  1a75024a98ba57132c2bd7439301eef72f64eb7672ecc618326993b5e970e60b "$reserved" \
  "Customize tokens returned from Okta: Add a custom claim to a token (custom authorization server only, Include in token type ID Token, Always, an Expression value)"
pin cache okta-groups-claim.html \
  "no version stated; $served" \
  "https://developer.okta.com/docs/guides/customize-tokens-groups-claim/main/" \
  ad19f6f3f6d6f7cee0ac3c5835af9445b310ab0a91017c35a498843e41532605 "$reserved" \
  "Customize tokens with a groups claim: Add a groups claim for a custom authorization server, a Groups filter matching a regex"
pin cache okta-authcode.html \
  "no version stated; $served" \
  "https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/" \
  911e1d7b966315260b0b4ddfff044ae4948285812a8823b04c94decbaedcdda9 "$reserved" \
  "Implement the Authorization Code grant: a Web Application integration, its Sign-in redirect URIs and the Basic authentication of the token request"
pinned_corpus okta "Okta OpenID Connect and OAuth 2.0 API" \
  "the Okta OpenID Connect and OAuth 2.0 API reference" \
  "The \"OpenID Connect & OAuth 2.0\" API reference of Okta's developer
documentation (the overview page that lists the claims of an Okta access
and ID token, client authentication, and the custom authorization server's
metadata), and the developer guides FerroSMART's Okta login cites. Okta
states that each page is \"Copyright © 2026 Okta. All rights reserved.\"
and grants no licence to copy it, so all are cache only and this repository
carries none of their content: the documentation cites them by section.

Examined and not taken: the \`okta/okta-developer-docs\` repository, the
source of the guides, which holds no source of the API reference pages and
declares no licence; the guides are pinned as developer.okta.com renders
them." \
  "" \
  "the \`okta\` issuer profile of #215, vendored by #222; FerroSMART's Okta login (#525, docs/architecture.md §13.18)"

say "done"
