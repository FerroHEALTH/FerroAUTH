#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/zitadel-docs.sh
#
# Vendors the ZITADEL documentation and API definitions that FerroSMART's
# ZITADEL example cites (#523) into docs/specs/zitadel/: the OpenID Connect
# claims, scopes and endpoints, how a user's roles reach a token, the
# custom login flow, self-hosting with compose, PostgreSQL, TLS and the
# custom domain, the first-instance setup steps and the official compose
# file, and the v2 API definitions the example's bootstrap calls to make the
# organization, the project, its roles, the users and the OIDC application,
# from zitadel/zitadel at the release tag the "ZITADEL documentation" row
# of docs/VERSIONS.md pins: the release FerroHEALTH/FerroEHR vendors and
# whose images it pins. A tag is mutable, so the script resolves it to a
# commit and records the commit. The repository is large, so each file is
# fetched on its own and checked against the commit's git blob id.
#
# Redistribution: the repository's LICENSE is the AGPL-3.0, and its
# LICENSING.md, vendored beside it, licenses `apps/docs/` and `proto/` under
# the Apache License 2.0. The pages and the definitions are taken under that
# grant; `cmd/setup/steps.yaml` and `deploy/compose/docker-compose.yml` are
# AGPL-3.0 files copied verbatim for citation and never built, linked or
# modified. The script fails if LICENSING.md stops granting Apache 2.0 for
# `apps/docs/` and `proto/`.
#
# Usage:
#   scripts/vendor/zitadel-docs.sh
#
# Requires: curl, shasum, jq.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl shasum jq

dest="docs/specs/zitadel"
docs="apps/docs/content"
paths=(
  LICENSE
  LICENSING.md
  "$docs/apis/openidoauth/claims.mdx"
  "$docs/apis/openidoauth/scopes.mdx"
  "$docs/apis/openidoauth/endpoints.mdx"
  "$docs/apis/openidoauth/grant-types.mdx"
  "$docs/guides/integrate/retrieve-user-roles.mdx"
  "$docs/guides/integrate/login-ui/oidc-standard.mdx"
  "$docs/guides/integrate/login-ui/username-password.mdx"
  "$docs/guides/integrate/login-ui/login-app.mdx"
  "$docs/self-hosting/deploy/compose.mdx"
  "$docs/self-hosting/manage/configure/configure.mdx"
  "$docs/self-hosting/manage/configure/example-zitadel-init-steps.yaml"
  "$docs/self-hosting/manage/custom-domain.mdx"
  "$docs/self-hosting/manage/tls_modes.mdx"
  "$docs/self-hosting/manage/login-client.mdx"
  "$docs/self-hosting/manage/database/_postgres.mdx"
  cmd/setup/steps.yaml
  deploy/compose/docker-compose.yml
  proto/zitadel/org/v2/org_service.proto
  proto/zitadel/project/v2/project_service.proto
  proto/zitadel/application/v2/application_service.proto
  proto/zitadel/application/v2/oidc.proto
  proto/zitadel/user/v2/user_service.proto
  proto/zitadel/authorization/v2/authorization_service.proto
  proto/zitadel/session/v2/session_service.proto
  proto/zitadel/oidc/v2/oidc_service.proto
)

pin="$(corpus_pin_cell "ZITADEL documentation")"
repo="$(corpus_pin_repo "$pin")"
tag="$(corpus_pin_tag "$pin")"
commit="$(corpus_resolve_tag "$repo" "$tag")"
want="$(corpus_pin_commit "$pin")"
[ "$commit" = "$want" ] || die "tag $tag of $repo resolves to $commit, the pin records $want"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "$repo tag $tag resolves to $commit"
committed="$(corpus_commit_date "$repo" "$commit")"
[ -n "$committed" ] || die "cannot read the date of $commit"
corpus_take_raw "$repo" "$commit" "$tmp/tree" "${paths[@]}"

grep -q 'Apache License 2.0' "$tmp/tree/LICENSING.md" || die "LICENSING.md grants no Apache License 2.0"
grep -q 'apps/docs/' "$tmp/tree/LICENSING.md" || die "LICENSING.md no longer names apps/docs/"
grep -q 'proto/' "$tmp/tree/LICENSING.md" || die "LICENSING.md no longer names proto/"

rm -rf "$dest"
mkdir -p "$dest"
cp -R "$tmp/tree/." "$dest/"

rows=""
while IFS= read -r file; do
  path="${file#"$dest"/}"
  rows="$rows
| \`$path\` | \`$(corpus_sha256 "$file")\` | \`$(corpus_blob_id "$file")\` |"
done < <(find "$dest" -type f ! -name PROVENANCE.md | LC_ALL=C sort)

files="$(corpus_file_count "$dest")"
digest="$(corpus_tree_digest "$dest")"
fetched="$(corpus_fetched)"

cat > "$dest/PROVENANCE.md" << PROV
<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the ZITADEL documentation and API definitions

Vendored verbatim by \`scripts/vendor/zitadel-docs.sh\`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/$repo>, the documentation under
  \`$docs/\`, the v2 API definitions under \`proto/\`, the setup steps and
  the official compose file
- Pin: tag \`$tag\`, which resolves to commit \`$commit\` ($committed)
- Fetched: $fetched, each file from raw.githubusercontent.com at the commit
  and checked against the git blob id the commit records
- Upstream licence: the repository is AGPL-3.0-only (\`LICENSE\`, vendored).
  Its \`LICENSING.md\`, vendored beside it, licenses \`apps/docs/\` and
  \`proto/\` under the Apache License 2.0, so the pages and the definitions
  are Apache-2.0. \`cmd/setup/steps.yaml\` and
  \`deploy/compose/docker-compose.yml\` are AGPL-3.0-only, copied verbatim
  for citation and never built, linked or modified. The files are
  unmodified.
- Images run, never vendored: \`ghcr.io/zitadel/zitadel\` (AGPL-3.0-only)
  and \`ghcr.io/zitadel/zitadel-login\` (the Login v2 UI, MIT), pinned by
  digest in docs/VERSIONS.md and run unmodified by the example
- Layout: the upstream paths, unchanged
- Files: $files
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$digest\`
- Read by: FerroSMART's ZITADEL example and the role claim reader of
  \`ferrohealth_smart::roles\` (#523)

## What is taken

- \`$docs/apis/openidoauth/\`: the claims ZITADEL puts in an ID Token,
  among them the project role claims, the reserved scopes, the endpoints
  and the grant types.
- \`$docs/guides/integrate/retrieve-user-roles.mdx\`: the shape of the role
  claim, an object whose member names are the roles.
- \`$docs/guides/integrate/login-ui/\`: the OIDC flow through the Login v2
  UI and the custom login flow a scripted login drives.
- \`$docs/self-hosting/\`: running ZITADEL under compose with PostgreSQL,
  the configuration, the first-instance steps, the custom domain, the TLS
  modes and the login client.
- \`cmd/setup/steps.yaml\` and \`deploy/compose/docker-compose.yml\`: the
  first-instance defaults and the official compose file.
- \`proto/zitadel/*/v2/\`: the organization, project, application, OIDC
  application settings, user, authorization, session and OIDC services the
  bootstrap calls.

| File | sha256 | git blob id |
|---|---|---|$rows
PROV

say "$files files, tree digest $digest"
say "done"
