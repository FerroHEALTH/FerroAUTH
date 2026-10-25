#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/cedar-docs.sh
#
# Vendors the Cedar policy language documentation into docs/specs/cedar-docs/:
# the policy, authorization and schema collections of the cedar-policy/
# cedar-docs repository (the language reference ferrohealth-authz's `cedar`
# feature implements against), with the repository's LICENSE, at the commit
# the "Cedar language documentation" row of docs/VERSIONS.md pins.
#
# Usage:
#   scripts/vendor/cedar-docs.sh
#
# Requires: curl, tar, shasum, jq.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl tar shasum jq

dest="docs/specs/cedar-docs"
paths=(docs/collections/_policies docs/collections/_auth docs/collections/_schema)

pin="$(corpus_pin_cell "Cedar language documentation")"
repo="$(corpus_pin_repo "$pin")"
commit="$(corpus_pin_commit "$pin")"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "$repo at $commit"
committed="$(corpus_commit_date "$repo" "$commit")"
[ -n "$committed" ] || die "cannot read the date of $commit"
tree_root="$(corpus_fetch "$repo" "$commit" "$tmp")"
[ -f "$tree_root/LICENSE" ] || die "the archive has no LICENSE"
grep -q "Apache License" "$tree_root/LICENSE" || die "the LICENSE is not the Apache License"

rm -rf "$dest"
mkdir -p "$dest"
corpus_take "$tree_root" "$dest" "${paths[@]}" LICENSE

files="$(corpus_file_count "$dest")"
digest="$(corpus_tree_digest "$dest")"
fetched="$(corpus_fetched)"

cat > "$dest/PROVENANCE.md" << PROV
<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the Cedar policy language documentation

Vendored verbatim by \`scripts/vendor/cedar-docs.sh\`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/$repo>, the trees ${paths[*]} with the
  repository's \`LICENSE\`
- Pin: commit \`$commit\` ($committed)
- Fetched: $fetched
- Files: $files
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$digest\`
- Upstream licence: the Apache License 2.0 of the repository, whose text is
  \`LICENSE\` here. The files are unmodified.
PROV

say "$files files, tree digest $digest"
say "done"
