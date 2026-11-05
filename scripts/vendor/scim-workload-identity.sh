#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/scim-workload-identity.sh
#
# Vendors the Microsoft Entra guide "Workload Identity Federation: A New
# Authentication Method for SCIM Provisioning" into
# docs/specs/scim-workload-identity/: the guide, the figures it links under
# media/workload-identity-federation/ and the repository's LICENSE, from
# AzureAD/SCIMReferenceCode at the commit the "SCIM workload identity
# federation guide" row of docs/VERSIONS.md pins. Each file is fetched on its
# own and checked against the commit's git blob id.
#
# Redistribution: the repository's LICENSE is the MIT License, which permits
# copying and distributing with the notice kept. The script fails if it
# stops being MIT.
#
# Usage:
#   scripts/vendor/scim-workload-identity.sh
#
# Requires: curl, shasum, jq.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl shasum jq

dest="docs/specs/scim-workload-identity"
guide="Workload-Identity-Federation-for-SCIM-Provisioning.md"
paths=(LICENSE "$guide" media/workload-identity-federation/)

pin="$(corpus_pin_cell "SCIM workload identity federation guide")"
repo="$(corpus_pin_repo "$pin")"
commit="$(corpus_pin_commit "$pin")"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "$repo at $commit"
committed="$(corpus_commit_date "$repo" "$commit")"
[ -n "$committed" ] || die "cannot read the date of $commit"
corpus_take_raw "$repo" "$commit" "$tmp/tree" "${paths[@]}"

grep -q '^ *MIT License' "$tmp/tree/LICENSE" || die "LICENSE no longer holds the MIT text"
dated="$(sed -nE 's/^\*\*Date:\*\* (.+)$/\1/p' "$tmp/tree/$guide" | head -n1)"
[ -n "$dated" ] || die "$guide states no date"

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

# Provenance: the SCIM workload identity federation guide

Vendored verbatim by \`scripts/vendor/scim-workload-identity.sh\`. Never
edit a file here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/$repo>, the file \`$guide\`
- Pin: commit \`$commit\` ($committed)
- Document: "Workload Identity Federation: A New Authentication Method for
  SCIM Provisioning", dated $dated in its own header
- Fetched: $fetched, each file from raw.githubusercontent.com at the commit
  and checked against the git blob id the commit records
- Upstream licence: the repository's \`LICENSE\`, the MIT License
  ("Copyright (c) Microsoft Corporation. Permission is hereby granted, free
  of charge, ... to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute ...", on the condition that "The above copyright notice and
  this permission notice shall be included in all copies or substantial
  portions of the Software"), vendored beside this file. The files are
  unmodified.
- Layout: the upstream paths, unchanged
- Files: $files
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$digest\`
- Read by: the RFC 7523 JWT bearer grant of #217, where Entra ID presents a
  workload identity assertion to an application's token endpoint, vendored
  by #222

## What is taken

The guide and every figure under \`media/workload-identity-federation/\`,
which it links. The reference code, the validation templates and the other
documents of the repository are not taken.

| File | sha256 | git blob id |
|---|---|---|$rows
PROV

say "$files files, tree digest $digest"
say "done"
