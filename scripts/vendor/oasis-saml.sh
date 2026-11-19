#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/oasis-saml.sh
#
# Vendors the OASIS SAML V2.0 standard into docs/specs/oasis-saml/: the
# Core, Bindings, Profiles and Metadata documents of the March 2005 OASIS
# Standard and the Errata 05 composite of May 2012, which FerroSMART's
# upstream SAML 2.0 login (FerroHEALTH/FerroSMART#688) cites. Each PDF is
# pinned by its docs.oasis-open.org URL and sha256
# (scripts/vendor/lib/pinned.sh). The OASIS copyright notice of each
# document allows it to be "copied and furnished to others" unmodified with
# the notice included, which the verbatim PDF carries.
#
# Usage:
#   scripts/vendor/oasis-saml.sh           fetch and write the tree
#   scripts/vendor/oasis-saml.sh --check   check the committed tree, offline
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

oasis='The OASIS notice each document carries: "This document and translations of it may be copied and furnished to others ... provided that the above copyright notice and this paragraph are included on all such copies"; the PDF is committed unmodified'
base="https://docs.oasis-open.org/security/saml/v2.0"

pin commit saml-core-2.0-os.pdf "SAML V2.0 OASIS Standard, 15 March 2005" \
  "$base/saml-core-2.0-os.pdf" \
  dc0890f88bfe862c9b39672bed76e2dcb0bedb03491cc41c161aea472b0468ab "$oasis" \
  'Assertions and Protocols: the assertion, the Response, the AuthnRequest, artifact resolution, the XML Signature profile (5.4) and encryption (6).'
pin commit saml-bindings-2.0-os.pdf "SAML V2.0 OASIS Standard, 15 March 2005" \
  "$base/saml-bindings-2.0-os.pdf" \
  80dde7953739eeb306484888ea128dd214e2b4a5dd16fbcbb231ef7ae18fa3f1 "$oasis" \
  'The SOAP (3.2), HTTP-Redirect (3.4), HTTP-POST (3.5) and HTTP-Artifact (3.6) bindings.'
pin commit saml-profiles-2.0-os.pdf "SAML V2.0 OASIS Standard, 15 March 2005" \
  "$base/saml-profiles-2.0-os.pdf" \
  5df9b874551941c7f03cb9270e67ea44f426b44a8fa642b8cf261064cc6f7de2 "$oasis" \
  'The Web Browser SSO profile (4.1).'
pin commit saml-metadata-2.0-os.pdf "SAML V2.0 OASIS Standard, 15 March 2005" \
  "$base/saml-metadata-2.0-os.pdf" \
  48656c21cc0cf26873ebec6792299de4f71c46ce5df73c707653b4c0b12117ae "$oasis" \
  'The entity and role descriptors, key descriptors and endpoints, and signed metadata (3).'
pin commit saml-v2.0-errata05-os.pdf "SAML Version 2.0 Errata 05, OASIS Standard, 1 May 2012" \
  "$base/errata05/os/saml-v2.0-errata05-os.pdf" \
  c9f6d7c4d6b147066a24715076ac8b62269429fae8e27d53a03cf0d73651ace3 "$oasis" \
  'The approved errata; E26 (assertions in the SSO profile), E43 and E93 (encryption), E46, E59, E81, E83, E91 and E92 are cited.'
pinned_corpus oasis-saml "OASIS SAML V2.0 standard" \
  "the OASIS SAML V2.0 standard and its Errata 05" \
  "The Core, Bindings, Profiles and Metadata documents of the SAML V2.0
OASIS Standard and the Errata 05 composite, committed verbatim under the
OASIS notice each carries. Attribution: OASIS Security Services Technical
Committee, *Security Assertion Markup Language (SAML) V2.0*." "" \
  "FerroSMART's upstream SAML 2.0 login (\`app/ferrosmart/src/saml/\`,
  FerroHEALTH/FerroSMART#688)"

say "done"
