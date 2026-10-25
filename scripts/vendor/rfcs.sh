#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/rfcs.sh
#
# Vendors the OAuth 2.0 and JOSE RFCs into docs/specs/rfc/, one text file
# each, from the RFC Editor. Every `RFC NNNN` row of docs/VERSIONS.md names
# the pin: the sha256 of the published text, which the script verifies. The
# RFC Editor's metadata for each is read too, and an RFC it reports obsoleted
# refuses the run, because a pin on an obsoleted document is a defect.
#
# Usage:
#   scripts/vendor/rfcs.sh
#
# Requires: curl, shasum, jq.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl shasum jq

dest="docs/specs/rfc"
editor="https://www.rfc-editor.org/rfc"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

declare -a rows=()
count=0
while IFS= read -r item; do
  number="${item#RFC }"
  grep -qE '^[0-9]+$' <<< "$number" || die "the row '$item' names no RFC number"
  pin="$(corpus_pin_cell "$item")"
  want="$(corpus_pin_field sha256 "$pin")"
  grep -qE '^[0-9a-f]{64}$' <<< "$want" || die "the $item row names no sha256"
  say "RFC $number"
  corpus_download "$editor/rfc$number.txt" "$tmp/rfc$number.txt" || die "download of RFC $number failed"
  got="$(corpus_sha256 "$tmp/rfc$number.txt")"
  [ "$got" = "$want" ] || die "RFC $number hashes to $got, the pin records $want"
  corpus_download "$editor/rfc$number.json" "$tmp/rfc$number.json" || die "download of the RFC $number metadata failed"
  title="$(jq -r '.title // empty' "$tmp/rfc$number.json")"
  published="$(jq -r '.pub_date // empty' "$tmp/rfc$number.json")"
  status="$(jq -r '.status // empty' "$tmp/rfc$number.json")"
  obsoleted="$(jq -r '(.obsoleted_by // []) | join(", ")' "$tmp/rfc$number.json")"
  updated="$(jq -r '(.updated_by // []) | join(", ")' "$tmp/rfc$number.json")"
  [ -n "$title" ] && [ -n "$published" ] && [ -n "$status" ] || die "the RFC $number metadata is incomplete"
  [ -z "$obsoleted" ] || die "RFC $number is obsoleted by $obsoleted; move the pin"
  rows+=("| RFC $number | $title | $published | $status | ${updated:-none} | \`$got\` |")
  count=$((count + 1))
done < <(corpus_pin_items "RFC ")
[ "$count" -gt 0 ] || die "docs/VERSIONS.md has no RFC row"

rm -rf "$dest"
mkdir -p "$dest"
cp "$tmp"/rfc*.txt "$dest/"
fetched="$(corpus_fetched)"
digest="$(corpus_tree_digest "$dest")"

cat > "$dest/PROVENANCE.md" << PROV
<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the OAuth 2.0 and JOSE RFCs

Vendored verbatim by \`scripts/vendor/rfcs.sh\` from the RFC Editor
(<$editor/>), the text form of each, as published. Never edit a file here:
change the pin in docs/VERSIONS.md and re-run the script.

- Fetched: $fetched
- Files: $count
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$digest\`
- Upstream licence: each RFC is "Copyright (c) <year> IETF Trust and the
  persons identified as the document authors. All rights reserved." and is
  "subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF
  Documents (<https://trustee.ietf.org/license-info>) in effect on the date
  of publication", as its Copyright Notice states. Section 3.c.i of the
  Trust Legal Provisions grants "to each person who wishes to exercise such
  rights ... a non-exclusive, royalty-free, worldwide right and license under
  all copyrights and rights of authors: i. to copy, publish, display and
  distribute IETF Contributions and IETF Documents in full and without
  modification" (TLP 5.0, effective 2015-03-25,
  <https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/>; RFC 6454,
  published in 2011, and RFC 6749 and RFC 6750, published in 2012, fall under
  TLP 4.0, effective
  2009-12-28, <https://trustee.ietf.org/license-info/IETF-TLP-4.htm>, whose
  section 3.c grants the same in the same words). Each file here is the
  whole document, unmodified, with
  every legend and notice it carries, which is what that grant covers. The
  BSD licence of section 4 covers only Code Components and is not relied on.

| Document | Title | Published | Status | Updated by | sha256 |
|---|---|---|---|---|---|
$(printf '%s\n' "${rows[@]}")

An "Updated by" entry names an RFC that changes the document without
replacing it; the design reads each update that bears on the resource
server role (RFC 9700 over RFC 6749 and RFC 6750, RFC 8725 over RFC 7519).
PROV

say "$count RFCs, tree digest $digest"
say "done"
