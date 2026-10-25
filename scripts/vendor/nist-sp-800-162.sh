#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/nist-sp-800-162.sh
#
# Vendors NIST Special Publication 800-162, "Guide to Attribute Based Access
# Control (ABAC) Definition and Considerations", into
# docs/specs/nist-sp-800-162/: the PDF NIST publishes, pinned by the sha256
# the "NIST SP 800-162 document" row of docs/VERSIONS.md records. The edition
# is the one with the updates of 2019-08-02, which its title page names; the
# script reads that line and refuses a file that does not carry it.
#
# Usage:
#   scripts/vendor/nist-sp-800-162.sh
#
# Requires: curl, shasum, pdftotext.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl shasum pdftotext

dest="docs/specs/nist-sp-800-162"
url="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-162.pdf"
file="NIST.SP.800-162.pdf"

pin="$(corpus_pin_cell "NIST SP 800-162 document")"
want="$(corpus_pin_field sha256 "$pin")"
grep -qE '^[0-9a-f]{64}$' <<< "$want" || die "the pin names no sha256"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "$url"
corpus_download "$url" "$tmp/$file" || die "download of $file failed"
got="$(corpus_sha256 "$tmp/$file")"
[ "$got" = "$want" ] || die "$file hashes to $got, the pin records $want"
updates="$(pdftotext -l 2 "$tmp/$file" - | grep -oE 'UPDATES AS OF [0-9-]+' | head -n1)"
[ -n "$updates" ] || die "$file names no update date on its title page"

rm -rf "$dest"
mkdir -p "$dest"
cp "$tmp/$file" "$dest/$file"
fetched="$(corpus_fetched)"

cat > "$dest/PROVENANCE.md" << PROV
<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream terms, not the licence of this repository. -->

# Provenance: NIST SP 800-162

Vendored verbatim by \`scripts/vendor/nist-sp-800-162.sh\`. Never edit the
file here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <$url>
- Edition: January 2014, its title page reading "INCLUDES $updates"
- Fetched: $fetched
- sha256: \`$got\`
- Upstream terms: the publication's own notice reads that it "is not subject
  to copyright in the United States. Attribution would, however, be
  appreciated by NIST." It is a work of the United States Government
  (17 U.S.C. §105). The attribution is this file: the material is NIST's.
PROV

say "$file ($updates), sha256 $got"
say "done"
