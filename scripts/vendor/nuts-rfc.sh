#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/nuts-rfc.sh
#
# Vendors Nuts RFC021, the VP Token Grant Type (the Verifiable Presentation
# as the authorization grant, the access token request and the introspection
# response), into docs/specs/nuts-rfc/, at the commit FerroHEALTH/FerroFED
# vendors it from. The caller classification of ferrohealth-smart (#215)
# reads an introspected Nuts token by its §6 and §8.
#
# The specifications live on the default branch of their repository, whose
# last tag predates RFC021, so the "Nuts RFC021" row of docs/VERSIONS.md pins
# a commit.
#
# Redistribution: the repository carries no licence file; the document states
# its own in its Copyright Notice, Creative Commons Attribution-ShareAlike
# 4.0 International. The script fails if the document stops saying so.
#
# Usage:
#   scripts/vendor/nuts-rfc.sh
#
# Requires: curl, tar, shasum, jq.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl tar shasum jq

dest="docs/specs/nuts-rfc"
document="rfc/rfc021-vp_token-grant-type.md"
statement='This document is released under the [Attribution-ShareAlike 4.0 International \(CC BY-SA 4.0\) license](https://creativecommons.org/licenses/by-sa/4.0/).'

pin="$(corpus_pin_cell "Nuts RFC021")"
repo="$(corpus_pin_repo "$pin")"
commit="$(corpus_pin_commit "$pin")"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "$repo at $commit"
committed="$(corpus_commit_date "$repo" "$commit")"
[ -n "$committed" ] || die "cannot read the date of $commit"
tree_root="$(corpus_fetch "$repo" "$commit" "$tmp")"

rm -rf "$dest"
mkdir -p "$dest"
corpus_take "$tree_root" "$dest" "$document"
grep -qF "$statement" "$dest/$document" ||
  die "$document no longer states the CC BY-SA 4.0 licence in its Copyright Notice"

sha="$(corpus_sha256 "$dest/$document")"
blob="$(corpus_blob_id "$dest/$document")"
files="$(corpus_file_count "$dest")"
digest="$(corpus_tree_digest "$dest")"
fetched="$(corpus_fetched)"

cat > "$dest/PROVENANCE.md" << PROV
<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: Nuts RFC021, the VP Token Grant Type

Vendored verbatim by \`scripts/vendor/nuts-rfc.sh\`. Never edit a file here:
change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/$repo>, the file \`$document\`
- Pin: commit \`$commit\` ($committed), the commit FerroHEALTH/FerroFED
  vendors its \`docs/specs/nuts-rfc/\` from
- Document: *RFC021 VP Token Grant Type*, published by the Nuts foundation
  as a Request for Comments
- Fetched: $fetched
- Upstream licence: the repository has no licence file. The document states
  its licence in its Copyright Notice, verbatim: "$statement"
  (<https://creativecommons.org/licenses/by-sa/4.0/legalcode>). The file is
  redistributed unmodified, with that notice, so no adaptation is made.
- Layout: the upstream path, unchanged
- Files: $files
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$digest\`
- Read by: #215 (the caller classification of an introspected Nuts token,
  §6 and §8), vendored by #222

| File | sha256 | git blob id |
|---|---|---|
| \`$document\` | \`$sha\` | \`$blob\` |
PROV

say "$files file, tree digest $digest"
say "done"
