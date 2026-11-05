#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/openehr-rm.sh
#
# Vendors the openEHR Reference Model Common chapter the party states of the
# party binding cite (#216, #249): `docs/common/master06-change_control_package.adoc`,
# the change control package whose "Abandoned and Inactive States" section
# defines `800|inactive|` and `801|abandoned|`, with the component manifest
# and the repository's licence file, from openEHR/specifications-RM at the
# development commit the "openEHR RM Common (development)" row of
# docs/VERSIONS.md pins, the commit FerroHEALTH/FerroEHR generates its RM
# from and FerroHEALTH/FerroBRIDGE vendors under the same path. The
# repository is large, so each file is fetched on its own and checked
# against the commit's git blob id.
#
# Redistribution: the repository's LICENSE is Creative Commons
# Attribution-ShareAlike 3.0 Unported, which permits distributing the work
# unmodified with the licence and attribution kept. The script fails if it
# changes.
#
# Usage:
#   scripts/vendor/openehr-rm.sh
#
# Requires: curl, shasum, jq.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl shasum jq

dest="docs/specs/openehr-rm/development"
chapter="docs/common/master06-change_control_package.adoc"
paths=(
  LICENSE
  manifest.json
  "$chapter"
)

pin="$(corpus_pin_cell "openEHR RM Common (development)")"
repo="$(corpus_pin_repo "$pin")"
commit="$(corpus_pin_commit "$pin")"
committed="$(corpus_commit_date "$repo" "$commit")"
[ -n "$committed" ] || die "$repo has no commit $commit"
say "$repo development commit $commit, committed $committed"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

corpus_take_raw "$repo" "$commit" "$tmp/tree" "${paths[@]}"

grep -q 'Attribution-ShareAlike 3.0' "$tmp/tree/LICENSE" ||
  die "the LICENSE is not Creative Commons Attribution-ShareAlike 3.0"
grep -q '^==== Abandoned and Inactive States' "$tmp/tree/$chapter" ||
  die "$chapter has no section Abandoned and Inactive States"
# shellcheck disable=SC2016 # the backticks are the chapter's Markdown code spans, matched literally
grep -qF '`800|inactive|` and `801|abandoned|`' "$tmp/tree/$chapter" ||
  die "$chapter no longer names 800|inactive| and 801|abandoned|"

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

# Provenance: the openEHR Reference Model Common chapter, development

Vendored verbatim by \`scripts/vendor/openehr-rm.sh\`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/$repo>, published at
  <https://specifications.openehr.org/releases/RM/development/common.html>
- Pin: commit \`$commit\` of the \`master\` branch ($committed), the
  development RM that FerroHEALTH/FerroEHR generates from and
  FerroHEALTH/FerroBRIDGE vendors under the same path. The
  \`manifest.json\` of that commit lists no 1.2.0 release: the generation
  is unreleased.
- Fetched: $fetched, each file from raw.githubusercontent.com at the commit
  and checked against the git blob id the commit records
- Upstream licence: Creative Commons Attribution-ShareAlike 3.0 Unported,
  as read in the repository's \`LICENSE\` file at the commit, vendored
  beside this file. The files are unmodified.
- Layout: the upstream paths of the commit, unchanged
- Files: $files
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$digest\`
- Read by: the party states of the party binding (#216, #249), cited as
  openEHR RM Common §Abandoned and Inactive States

## What is taken

\`$chapter\`, the Common IM chapter "Change Control Package", whose
"Version Lifecycle" section lists the lifecycle states (\`800|inactive|\`
and \`801|abandoned|\` among them) and whose "Abandoned and Inactive
States" section defines the two, with the component manifest. The other
chapters, the class definitions and the UML diagrams are not taken.

| File | sha256 | git blob id |
|---|---|---|$rows
PROV

say "$files files, tree digest $digest"
say "done"
