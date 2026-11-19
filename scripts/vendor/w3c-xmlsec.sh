#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/w3c-xmlsec.sh
#
# Vendors the W3C XML security Recommendations into docs/specs/w3c-xmlsec/:
# XML Signature Syntax and Processing 1.1, XML Encryption Syntax and
# Processing 1.1, Exclusive XML Canonicalization 1.0 and Canonical XML 1.0,
# which the eHDSI assertion check and FerroSMART's upstream SAML 2.0 login
# (FerroHEALTH/FerroSMART#688) cite. Each page is pinned by its dated
# www.w3.org/TR URL and sha256 (scripts/vendor/lib/pinned.sh), under the W3C
# Document License each page links.
#
# Usage:
#   scripts/vendor/w3c-xmlsec.sh           fetch and write the tree
#   scripts/vendor/w3c-xmlsec.sh --check   check the committed tree, offline
#
# Requires: curl, shasum, awk.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "${1:-}" in
  --check) export PINNED_CHECK=1 ;;
  '') ;;
  *)
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"
# shellcheck source=scripts/vendor/lib/pinned.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/pinned.sh"

corpus_require curl shasum awk
pinned_begin

w3c='The W3C Document License (https://www.w3.org/copyright/document-license/), which each page links: copies of the document may be distributed unmodified with its copyright notice'

pin commit xmldsig-core1.html "W3C Recommendation, 11 April 2013" \
  https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/ \
  4924a334deb880e7e18b54cd6db037aa6b4d0186e626a26d636c124f8a2e07a3 "$w3c" \
  'XML Signature 1.1: the signature syntax, the reference processing and the algorithm requirements (6.1).'
pin commit xmlenc-core1.html "W3C Recommendation, 11 April 2013" \
  https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/ \
  40e83298cc2e53c565bebf8b8345c14edabea77d56a3a3698ca438730afec1ce "$w3c" \
  'XML Encryption 1.1: EncryptedData and EncryptedKey, AES-GCM, AES-CBC and its padding, RSA-OAEP (5).'
pin commit xml-exc-c14n.html "W3C Recommendation, 18 July 2002" \
  https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/ \
  10b1ec71542db546b311a3e600589339505b9099bc60affafa4204ece31807e3 "$w3c" \
  'Exclusive XML Canonicalization 1.0, the one canonicalization accepted.'
pin commit xml-c14n.html "W3C Recommendation, 15 March 2001" \
  https://www.w3.org/TR/2001/REC-xml-c14n-20010315 \
  09c02ef3bc0f8364b00b16fb06092637c08e8f38cf223d47a5862eacc2956bc0 "$w3c" \
  'Canonical XML 1.0, whose text and attribute rules (2.2, 2.3) the exclusive form inherits.'
pinned_corpus w3c-xmlsec "W3C XML security Recommendations" \
  "the W3C XML Signature, XML Encryption and canonicalization Recommendations" \
  "XML Signature 1.1, XML Encryption 1.1, Exclusive XML Canonicalization
1.0 and Canonical XML 1.0, committed verbatim under the W3C Document
License. Attribution: World Wide Web Consortium." "" \
  "the eHDSI assertion check and the shared \`xml\` module of
  \`ferrohealth-smart\`, and FerroSMART's upstream SAML 2.0 login
  (FerroHEALTH/FerroSMART#688)"

say "done"
