#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/ihe-iua.sh
#
# Vendors the IHE Internet User Authorization (IUA) Technical Framework
# Supplement into docs/specs/ihe-iua/: the supplement's Markdown source, which
# defines Get Access Token [ITI-71], Incorporate Access Token [ITI-72],
# Introspect Token [ITI-102] and Get Authorization Server Metadata
# [ITI-103], its figures, and the repository's licence file.
#
# The caller classification of ferrohealth-smart (#215) reads the IUA access
# token claims of ITI-71 (`sub`, `extensions.ihe_iua`), so the text it is held
# to is pinned here (#222), at the edition FerroHEALTH/FerroFED vendors.
#
# IUA is published as a supplement in IHE's own repository, with no FHIR
# package. The "IHE IUA supplement" row of docs/VERSIONS.md pins a tag and the
# commit it resolved to; a tag is mutable, so the script refuses a tag that
# now resolves elsewhere, records the git blob id of each file, and checks
# that the supplement declares the revision the tag names.
#
# Redistribution: the repository is licensed CC-BY-4.0 (its LICENSE, vendored
# beside the text), and the IHE Technical Frameworks General Introduction §9
# grants every user a licence to reproduce and distribute IHE Technical
# Documents under IHE International's copyrights. The script fails if the
# licence file stops being CC-BY-4.0.
#
# Usage:
#   scripts/vendor/ihe-iua.sh
#
# Requires: curl, tar, shasum, jq.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl tar shasum jq

dest="docs/specs/ihe-iua"
supplement="IHE_ITI_Suppl_IUA.md"
paths=("$supplement" "media" "LICENSE")

pin="$(corpus_pin_cell "IHE IUA supplement")"
repo="$(corpus_pin_repo "$pin")"
tag="$(corpus_pin_tag "$pin")"
commit="$(corpus_resolve_tag "$repo" "$tag")"
want="$(corpus_pin_commit "$pin")"
[ "$commit" = "$want" ] || die "tag $tag of $repo resolves to $commit, the pin records $want"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "$repo tag $tag resolves to $commit"
tree_root="$(corpus_fetch "$repo" "$commit" "$tmp")"

rm -rf "$dest"
mkdir -p "$dest"
corpus_take "$tree_root" "$dest" "${paths[@]}"

revision="$(sed -nE 's/^\*\*Revision ([0-9.]+) - (.+)\*\*[[:space:]]*$/\1/p' "$dest/$supplement" | head -n1)"
status="$(sed -nE 's/^\*\*Revision ([0-9.]+) - (.+)\*\*[[:space:]]*$/\2/p' "$dest/$supplement" | head -n1)"
published="$(sed -nE 's/^Date:[[:space:]]*(.+[0-9])[[:space:]]*$/\1/p' "$dest/$supplement" | head -n1)"
[ -n "$revision" ] || die "$supplement declares no revision"
[ "$revision" = "$tag" ] || die "$supplement declares revision $revision, the tag names $tag"
[ -n "$published" ] || die "$supplement declares no date"
for transaction in ITI-71 ITI-72; do
  grep -qE "^## 3\.[0-9]+ .*\[$transaction\]" "$dest/$supplement" \
    || die "$supplement defines no $transaction section"
done
grep -q '^Attribution 4.0 International' "$dest/LICENSE" \
  || die "the repository LICENSE is not Creative Commons Attribution 4.0 International"

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

# Provenance: the IHE IUA Technical Framework Supplement

Vendored verbatim by \`scripts/vendor/ihe-iua.sh\`. Never edit a file here:
change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/$repo>, rendered at
  <https://profiles.ihe.net/ITI/IUA/index.html>
- Pin: tag \`$tag\`, which resolves to commit \`$commit\`
- Document: Internet User Authorization (IUA), Revision $revision - $status,
  dated $published
- Fetched: $fetched
- Upstream licence: the repository's \`LICENSE\`, Creative Commons
  Attribution 4.0 International, vendored beside this file. The IHE
  Technical Frameworks General Introduction §9
  (<https://profiles.ihe.net/GeneralIntro/ch-9.html>) also grants every user
  of IHE Technical Documents a licence to reproduce and distribute them under
  IHE International's copyrights. The supplement reproduces no table of a
  base standard; it refers to OAuth 2.0 RFCs and HL7 FHIR by link.
- Layout: the upstream paths, unchanged
- Files: $files
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$digest\`
- Read by: #215 (the caller classification's reading of the ITI-71
  access token claims), vendored by #222

## What is taken

\`$supplement\` is the supplement's whole text: Volume 1 §34 (the IUA
profile) and Volume 2 §3.71 Get Access Token [ITI-71], §3.72 Incorporate
Access Token [ITI-72], §3.102 Introspect Token [ITI-102] and §3.103 Get
Authorization Server Metadata [ITI-103]. \`media/\` is the upstream
directory whole: the figures the text links and the slide deck the actor
diagrams are drawn in, which the text does not link but which is kept so
the directory stays as the publisher ships it. The repository's build
script, stylesheet, code system, issue templates and README are not taken.
The status is the document's own: a Trial Implementation supplement may be
amended before it is incorporated into the Technical Framework.

| File | sha256 | git blob id |
|---|---|---|$rows
PROV

say "$files files, tree digest $digest"
say "done"
