#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/federation-spec.sh
#
# Vendors Annex B (the Dutch Generic Functions) of the openEHR Federation
# Tier with AQL specification 1.0.1 into docs/specs/federation-spec/, with
# the repository's LICENSE and the `antora.yml` that declares the version,
# at the commit FerroHEALTH/FerroFED vendors the whole specification from.
# The caller classification (#215) reads its §B.4a, the VWS memo concept
# v0.9 reading of `authorization_details`.
#
# Upstream has not tagged 1.0.1, so the "Federation Tier with AQL
# specification" row of docs/VERSIONS.md pins a commit. Each file is
# checked against the git blob id the commit records (corpus_take_raw), and
# the script fails when `antora.yml` stops declaring the pinned version or
# the LICENSE stops being CC0 1.0.
#
# Usage:
#   scripts/vendor/federation-spec.sh
#
# Requires: curl, shasum, jq.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl shasum jq

dest="docs/specs/federation-spec"
annex="modules/ROOT/pages/annex-b-dutch-gf.adoc"
version="1.0.1"

pin="$(corpus_pin_cell "Federation Tier with AQL specification")"
repo="$(corpus_pin_repo "$pin")"
commit="$(corpus_pin_commit "$pin")"

say "$repo at $commit"
committed="$(corpus_commit_date "$repo" "$commit")"
[ -n "$committed" ] || die "cannot read the date of $commit"

rm -rf "$dest"
mkdir -p "$dest"
corpus_take_raw "$repo" "$commit" "$dest" LICENSE antora.yml "$annex"
grep -qF "spec-version: '$version'" "$dest/antora.yml" ||
  die "antora.yml at $commit does not declare spec-version $version"
status="$(sed -n "s/^ *spec-status: '\(.*\)'$/\1/p" "$dest/antora.yml")"
dated="$(sed -n "s/^ *spec-date: '\(.*\)'$/\1/p" "$dest/antora.yml")"
[ -n "$status" ] && [ -n "$dated" ] || die "antora.yml at $commit names no status or date"
head -n 3 "$dest/LICENSE" | grep -qF "CC0 1.0 Universal" ||
  die "the LICENSE at $commit is no longer CC0 1.0 Universal"

rows=""
for path in LICENSE antora.yml "$annex"; do
  rows="$rows
| \`$path\` | \`$(corpus_sha256 "$dest/$path")\` | \`$(corpus_blob_id "$dest/$path")\` |"
done
files="$(corpus_file_count "$dest")"
digest="$(corpus_tree_digest "$dest")"
fetched="$(corpus_fetched)"

cat > "$dest/PROVENANCE.md" << PROV
<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the Federation Tier with AQL specification, Annex B

Vendored verbatim by \`scripts/vendor/federation-spec.sh\`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/$repo>
- Pin: commit \`$commit\` ($committed), which upstream has not tagged, the
  commit FerroHEALTH/FerroFED vendors its \`docs/specs/federation-spec/\` from
- Declared version: \`spec-version: '$version'\`, status \`$status\`, dated
  \`$dated\` (\`antora.yml\`)
- Fetched: $fetched
- Upstream licence: Creative Commons Zero v1.0 Universal (CC0 1.0), the
  repository's \`LICENSE\` file, vendored beside this file
- Layout: the upstream paths, unchanged; only Annex B is taken, and its
  cross-references into the normative body (\`xref:\`) are not resolved here
- Files: $files
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$digest\`
- Read by: the caller classification (#215: §B.4a, the VWS memo
  *Harmonisatie van authenticatie en autorisatie voor de
  gegevensuitwisselingen BgZ en eOverdracht*, concept v0.9, and the
  \`authorization_details\` object it carries), vendored by #224

| File | sha256 | git blob id |
|---|---|---|$rows
PROV

say "$files files, tree digest $digest"
say "done"
