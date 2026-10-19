#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/openid-connect-discovery.sh
#
# Vendors OpenID Connect Discovery 1.0 into docs/specs/openid-connect-discovery/:
# the errata edition the "OpenID Connect Discovery 1.0 document" row of
# docs/VERSIONS.md pins, at its own immutable URL, verified against the
# recorded sha256. The script also reads the unversioned URL the OpenID
# Foundation serves the current edition at and refuses the run when it no
# longer carries the same bytes, because that is a new errata set to re-pin.
#
# Usage:
#   scripts/vendor/openid-connect-discovery.sh
#
# Requires: curl, shasum.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl shasum

dest="docs/specs/openid-connect-discovery"
site="https://openid.net/specs"
current="openid-connect-discovery-1_0.html"

pin="$(corpus_pin_cell "OpenID Connect Discovery 1.0 document")"
file="$(awk '{ print $1; exit }' <<< "$pin")"
want="$(corpus_pin_field sha256 "$pin")"
case "$file" in
  openid-connect-discovery-1_0-*.html) ;;
  *) die "the pin names no errata edition: '$file'" ;;
esac
grep -qE '^[0-9a-f]{64}$' <<< "$want" || die "the pin names no sha256"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "$site/$file"
corpus_download "$site/$file" "$tmp/$file" || die "download of $file failed"
got="$(corpus_sha256 "$tmp/$file")"
[ "$got" = "$want" ] || die "$file hashes to $got, the pin records $want"
corpus_download "$site/$current" "$tmp/$current" || die "download of $current failed"
cmp -s "$tmp/$file" "$tmp/$current" ||
  die "$current no longer carries the bytes of $file: a newer errata set is published, re-pin"
# The document's own date line is the proof of which edition this is.
dated="$(grep -oE '(January|February|March|April|May|June|July|August|September|October|November|December) [0-9]{1,2}, [0-9]{4}' "$tmp/$file" | head -n1)"
[ -n "$dated" ] || die "$file carries no date line"

rm -rf "$dest"
mkdir -p "$dest"
cp "$tmp/$file" "$dest/$file"
fetched="$(corpus_fetched)"

cat > "$dest/PROVENANCE.md" << PROV
<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: OpenID Connect Discovery 1.0

Vendored verbatim by \`scripts/vendor/openid-connect-discovery.sh\`. Never
edit the file here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <$site/$file>, the edition's own immutable URL
- Edition: the one dated $dated, which is the edition the unversioned
  <$site/$current> served when fetched (the script checks the two are
  byte-identical)
- Fetched: $fetched
- sha256: \`$got\`
- Upstream licence: the specification's Appendix B, Notices: "Copyright (c)
  2023 The OpenID Foundation. The OpenID Foundation (OIDF) grants to any
  Contributor, developer, implementer, or other interested party a
  non-exclusive, royalty free, worldwide copyright license to reproduce,
  prepare derivative works from, distribute, perform and display, this
  Implementers Draft or Final Specification solely for the purposes of (i)
  developing specifications, and (ii) implementing Implementers Drafts and
  Final Specifications based on such documents, provided that attribution be
  made to the OIDF as the source of the material, but that such attribution
  does not indicate an endorsement by the OIDF." This copy exists to
  implement the specification, and the attribution is this file: the
  material is the OpenID Foundation's.
PROV

say "$file dated $dated, sha256 $got"
say "done"
