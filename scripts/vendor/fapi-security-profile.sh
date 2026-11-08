#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/fapi-security-profile.sh
#
# Vendors the FAPI 2.0 Security Profile into docs/specs/fapi-security-profile/:
# the Final Specification the "FAPI 2.0 Security Profile document" row of
# docs/VERSIONS.md pins, at its own immutable URL, verified against the
# recorded sha256.
#
# Usage:
#   scripts/vendor/fapi-security-profile.sh
#
# Requires: curl, shasum.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl shasum

dest="docs/specs/fapi-security-profile"
site="https://openid.net/specs"

pin="$(corpus_pin_cell "FAPI 2.0 Security Profile document")"
file="$(awk '{ print $1; exit }' <<< "$pin")"
want="$(corpus_pin_field sha256 "$pin")"
case "$file" in
  fapi-security-profile-2_0-final*.html) ;;
  *) die "the pin names no final edition: '$file'" ;;
esac
grep -qE '^[0-9a-f]{64}$' <<< "$want" || die "the pin names no sha256"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "$site/$file"
corpus_download "$site/$file" "$tmp/$file" || die "download of $file failed"
got="$(corpus_sha256 "$tmp/$file")"
[ "$got" = "$want" ] || die "$file hashes to $got, the pin records $want"
# The document's own publication date is the proof of which edition this is.
dated="$(grep -oE '<time datetime="[0-9]{4}-[0-9]{2}-[0-9]{2}" class="published">' "$tmp/$file" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -n1)"
[ -n "$dated" ] || die "$file carries no publication date"

rm -rf "$dest"
mkdir -p "$dest"
cp "$tmp/$file" "$dest/$file"
fetched="$(corpus_fetched)"

cat > "$dest/PROVENANCE.md" << PROV
<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: FAPI 2.0 Security Profile

Vendored verbatim by \`scripts/vendor/fapi-security-profile.sh\`. Never
edit the file here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <$site/$file>, the Final Specification's own immutable URL
- Edition: the Final Specification published $dated
- Fetched: $fetched
- sha256: \`$got\`
- Upstream licence: the specification's Notices: "Copyright (c) 2025 The
  OpenID Foundation. The OpenID Foundation (OIDF) grants to any
  Contributor, developer, implementer, or other interested party a
  non-exclusive, royalty free, worldwide copyright license to reproduce,
  prepare derivative works from, distribute, perform and display, this
  Implementers Draft, Final Specification, or Final Specification
  Incorporating Errata Corrections solely for the purposes of (i)
  developing specifications, and (ii) implementing Implementers Drafts,
  Final Specifications, and Final Specification Incorporating Errata
  Corrections based on such documents, provided that attribution be made
  to the OIDF as the source of the material, but that such attribution
  does not indicate an endorsement by the OIDF." This copy exists to
  implement the specification, and the attribution is this file: the
  material is the OpenID Foundation's.
PROV

say "$file published $dated, sha256 $got"
say "done"
