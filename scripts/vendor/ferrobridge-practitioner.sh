#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/ferrobridge-practitioner.sh
#
# Vendors what the Inferno lane (#520) needs to serve a Practitioner through
# FerroBRIDGE's FHIR facade into docs/specs/ferrobridge-practitioner/: the
# ADL 1.4 PERSON template FerroBRIDGE's demographic suite runs on, and the
# FHIRconnect party context and model mapping of a Practitioner onto it,
# from FerroHEALTH/FerroBRIDGE at the release tag the "FerroBRIDGE
# Practitioner mapping" row of docs/VERSIONS.md pins: the release whose
# image the lane runs. A tag is mutable, so the script resolves it to a
# commit and records the commit, and each file is checked against the
# commit's git blob id.
#
# Redistribution: FerroBRIDGE is BUSL-1.1 under the same Licensor as this
# repository, and the files are copied verbatim with their SPDX headers.
#
# Usage:
#   scripts/vendor/ferrobridge-practitioner.sh
#
# Requires: curl, shasum, jq.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl shasum jq

dest="docs/specs/ferrobridge-practitioner"
fixtures="app/ferrobridge-server/tests/it/fixtures_demographic"
paths=(
  LICENSE
  tools/ferrobridge-testkit/fixtures/opt/person.opt
  "$fixtures/ferrobridge_demographic_practitioner.context.yml"
  "$fixtures/ferrobridge_demographic_practitioner.yml"
)

pin="$(corpus_pin_cell "FerroBRIDGE Practitioner mapping")"
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
grep -q 'Business Source License 1.1' "$tmp/tree/LICENSE" || die "LICENSE is not the Business Source License 1.1"

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
<!-- This file describes vendored material; the bytes beside it are copied
     verbatim and keep the licence their headers and LICENSE name. -->

# Provenance: the FerroBRIDGE Practitioner mapping

Vendored verbatim by \`scripts/vendor/ferrobridge-practitioner.sh\`. Never
edit a file here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/$repo>
- Pin: tag \`$tag\`, which resolves to commit \`$commit\` ($committed), the
  release whose image the Inferno lane runs
- Fetched: $fetched, each file from raw.githubusercontent.com at the commit
  and checked against the git blob id the commit records
- Licence: the Business Source License 1.1 (\`LICENSE\`), the Licensor of
  this repository; the files are unmodified
- Layout: the upstream paths, unchanged
- Files: $files
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$digest\`
- Read by: the Inferno lane (#520), which loads the template into FerroEHR
  and the two mappings into FerroBRIDGE so the facade serves the person's
  \`fhirUser\` as a \`Practitioner\`

## What is taken

- \`tools/ferrobridge-testkit/fixtures/opt/person.opt\`: the ADL 1.4 PERSON
  template \`ferrobridge.person.v1\`.
- \`$fixtures/ferrobridge_demographic_practitioner.context.yml\` and
  \`ferrobridge_demographic_practitioner.yml\`: the FHIRconnect party
  context and model mapping of the base \`Practitioner\` onto it.

| File | sha256 | git blob id |
|---|---|---|$rows
PROV

say "$files files, tree digest $digest"
say "done"
