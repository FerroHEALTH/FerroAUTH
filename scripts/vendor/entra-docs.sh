#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/entra-docs.sh
#
# Vendors the Microsoft identity platform documents the `entra` issuer
# profile and the `idp-entra` adapter cite (#215, #216, #217, #221) into
# docs/specs/entra-docs/: the access token claims reference (with its groups
# overage section), the optional claims reference and the on-behalf-of flow,
# with the two include files and the figure the flow page links, and the
# repository's README, LICENSE and LICENSE-CODE, from MicrosoftDocs/
# entra-docs at the commit the "Microsoft Entra documentation" row of
# docs/VERSIONS.md pins. The repository is large, so each file is fetched on
# its own and checked against the commit's git blob id.
#
# Redistribution: the README grants the documentation under Creative Commons
# Attribution 4.0 International and the code under MIT, while the LICENSE
# file it names for the documentation holds the MIT text. Both grants allow a
# verbatim copy with attribution, and the PROVENANCE.md quotes both. The
# script fails if either statement changes.
#
# Usage:
#   scripts/vendor/entra-docs.sh
#
# Requires: curl, shasum, jq.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl shasum jq

dest="docs/specs/entra-docs"
base="docs/identity-platform"
paths=(
  README.md
  LICENSE
  LICENSE-CODE
  "$base/access-token-claims-reference.md"
  "$base/optional-claims-reference.md"
  "$base/v2-oauth2-on-behalf-of-flow.md"
  "$base/includes/remind-not-to-relay-token-nonaud.md"
  "$base/includes/remind-not-to-validate-access-tokens.md"
  "$base/media/v2-oauth2-on-behalf-of-flow/protocols-oauth-on-behalf-of-flow.png"
)
grant='Microsoft and any contributors grant you a license to the Microsoft documentation and other content in this repository under the [Creative Commons Attribution 4.0 International Public License](https://creativecommons.org/licenses/by/4.0/legalcode), see the [LICENSE](LICENSE) file, and grant you a license to any code in the repository under the [MIT License](https://opensource.org/licenses/MIT), see the [LICENSE-CODE](LICENSE-CODE) file.'

pin="$(corpus_pin_cell "Microsoft Entra documentation")"
repo="$(corpus_pin_repo "$pin")"
commit="$(corpus_pin_commit "$pin")"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "$repo at $commit"
committed="$(corpus_commit_date "$repo" "$commit")"
[ -n "$committed" ] || die "cannot read the date of $commit"
corpus_take_raw "$repo" "$commit" "$tmp/tree" "${paths[@]}"

grep -qF "$grant" "$tmp/tree/README.md" || die "README.md no longer carries the licence grant"
grep -q '^ *MIT License' "$tmp/tree/LICENSE" || die "LICENSE no longer holds the MIT text"
grep -q '^The MIT License (MIT)' "$tmp/tree/LICENSE-CODE" || die "LICENSE-CODE no longer holds the MIT text"
grep -q '^### Groups overage claim' "$tmp/tree/$base/access-token-claims-reference.md" ||
  die "the access token claims reference has no groups overage section"

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

# Provenance: the Microsoft identity platform documents

Vendored verbatim by \`scripts/vendor/entra-docs.sh\`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/$repo>, rendered under
  <https://learn.microsoft.com/en-us/entra/identity-platform/>
- Pin: commit \`$commit\` ($committed)
- Fetched: $fetched, each file from raw.githubusercontent.com at the commit
  and checked against the git blob id the commit records
- Upstream licence: the repository's \`README.md\` states, verbatim:
  "$grant" The \`LICENSE\` file it names for the documentation holds the
  MIT License text ("Copyright (c) Microsoft Corporation. Permission is
  hereby granted, free of charge, ... to deal in the Software without
  restriction, including without limitation the rights to use, copy, modify,
  merge, publish, distribute ..."), and \`LICENSE-CODE\` holds the MIT text
  too. Both statements are recorded here because they disagree; each allows
  a verbatim copy with the notice and attribution kept, which is what this
  directory is. The attribution is this file: the documents are
  Microsoft's. The README also states that the licences grant no right to
  Microsoft's names, logos or trademarks.
- Layout: the upstream paths, unchanged
- Files: $files
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$digest\`
- Read by: the \`entra\` issuer profile of #215, the person key of #216, the
  on-behalf-of grant of #217 and the \`idp-entra\` groups overage adapter of
  #221, vendored by #222

## What is taken

\`$base/access-token-claims-reference.md\` ("Access token claims
reference", with its "Groups overage claim" section),
\`$base/optional-claims-reference.md\` ("Optional claims reference", the
\`idtyp\` and \`acct\` claims) and \`$base/v2-oauth2-on-behalf-of-flow.md\`
("Microsoft identity platform and OAuth2.0 On-Behalf-Of flow"), with the
two include files and the one figure the flow page links. The other pages
and media of the repository are not taken.

| File | sha256 | git blob id |
|---|---|---|$rows
PROV

say "$files files, tree digest $digest"
say "done"
