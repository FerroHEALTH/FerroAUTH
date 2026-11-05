#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/keycloak-docs.sh
#
# Vendors the Keycloak documentation the `keycloak` issuer profile cites
# (#215, #217) into docs/specs/keycloak-docs/: the token exchange chapter of
# the securing applications guide with the template its preview notices are
# rendered from, and the server administration guide's sections on service
# accounts (with the admin CLI section that names a service account's user),
# protocol mappers, audience support and identity brokering, the server
# guide's container chapter the live Keycloak case starts the image by, and
# the two sources that name the audience mapper's provider id and config
# keys (#239), with the repository's LICENSE.txt,
# from keycloak/keycloak at the release tag the "Keycloak documentation" row
# of docs/VERSIONS.md pins. A tag is mutable, so the script resolves it to a
# commit and records the commit. The repository is large, so each file is
# fetched on its own and checked against the commit's git blob id.
#
# Redistribution: the repository's LICENSE.txt is the Apache License 2.0,
# which permits reproducing and distributing the work unmodified with the
# licence kept beside it. The script fails if it stops being Apache 2.0.
#
# Usage:
#   scripts/vendor/keycloak-docs.sh
#
# Requires: curl, shasum, jq.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl shasum jq

dest="docs/specs/keycloak-docs"
admin="docs/documentation/server_admin/topics"
mappers="services/src/main/java/org/keycloak/protocol/oidc/mappers"
paths=(
  LICENSE.txt
  docs/guides/securing-apps/token-exchange.adoc
  docs/guides/templates/features.adoc
  docs/guides/server/containers.adoc
  "$admin/clients/oidc/proc-using-a-service-account.adoc"
  "$admin/admin-cli.adoc"
  "$admin/clients/con-protocol-mappers.adoc"
  "$admin/clients/proc-creating-mappers.adoc"
  "$admin/clients/oidc/con-audience.adoc"
  "$admin/identity-broker.adoc"
  "$admin/identity-broker/"
  "$mappers/AudienceProtocolMapper.java"
  "$mappers/OIDCAttributeMapperHelper.java"
)

pin="$(corpus_pin_cell "Keycloak documentation")"
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

grep -q 'Apache License' "$tmp/tree/LICENSE.txt" || die "LICENSE.txt is not the Apache License"
grep -q 'Version 2.0, January 2004' "$tmp/tree/LICENSE.txt" || die "LICENSE.txt is not version 2.0"

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

# Provenance: the Keycloak documentation

Vendored verbatim by \`scripts/vendor/keycloak-docs.sh\`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/$repo>, rendered as the Keycloak $tag
  guides at <https://www.keycloak.org/documentation>
- Pin: tag \`$tag\`, which resolves to commit \`$commit\` ($committed)
- Fetched: $fetched, each file from raw.githubusercontent.com at the commit
  and checked against the git blob id the commit records
- Upstream licence: the repository's \`LICENSE.txt\`, the Apache License,
  Version 2.0, January 2004, vendored beside this file. Its §4 permits
  reproducing and distributing copies of the work in any medium, with a
  copy of the licence given to every recipient. The files are unmodified.
- Layout: the upstream paths, unchanged
- Files: $files
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$digest\`
- Read by: the \`keycloak\` issuer profile of #215, the token exchange
  grant of #217 and the live Keycloak case of #239, vendored by #222 and #239

## What is taken

- \`docs/guides/securing-apps/token-exchange.adoc\`: "Configuring and using
  token exchange", the standard (V2) and legacy (V1) exchange, delegation
  and the limitation that "{project_name} Token exchange does not yet have
  support for the \`resource\` parameter". In Keycloak 26 the chapter lives
  in the securing applications guide, not the server administration guide.
- \`docs/guides/templates/features.adoc\`: the \`techpreview\` and
  \`techpreviewdeprecated\` macros, whose text ("is *Preview* and is not
  fully supported") the token exchange chapter's preview notices render.
- \`$admin/clients/oidc/proc-using-a-service-account.adoc\`: "Using a
  service account".
- \`$admin/admin-cli.adoc\`: the admin CLI chapter, whose section "Adding
  or removing roles for client's service account" states that "A
  client's service account is a user account with username
  \`service-account-CLIENT_ID\`".
- \`$admin/clients/con-protocol-mappers.adoc\` and
  \`$admin/clients/proc-creating-mappers.adoc\`: "OIDC token and SAML
  assertion mappings" and creating protocol mappers, with the impersonator
  mappers.
- \`$admin/identity-broker.adoc\` and \`$admin/identity-broker/\`:
  "Integrating identity providers", whole.
- \`$admin/clients/oidc/con-audience.adoc\`: "Audience support", the
  audience mapper a client's access tokens carry \`aud\` by.
- \`docs/guides/server/containers.adoc\`: "Running Keycloak in a
  container", whose section "Trying Keycloak in development mode" runs the
  image with \`start-dev\` and the \`KC_BOOTSTRAP_ADMIN_USERNAME\` and
  \`KC_BOOTSTRAP_ADMIN_PASSWORD\` variables.
- \`$mappers/AudienceProtocolMapper.java\` and
  \`$mappers/OIDCAttributeMapperHelper.java\`: the audience mapper's
  provider id (\`PROVIDER_ID = "oidc-audience-mapper"\`), its
  \`included.custom.audience\` key and the \`access.token.claim\` key, which
  no guide states. The source files carry the same Apache License 2.0
  header.

The guides' images, and the other chapters the \`include::\` lines of an
index name, are not taken.

| File | sha256 | git blob id |
|---|---|---|$rows
PROV

say "$files files, tree digest $digest"
say "done"
