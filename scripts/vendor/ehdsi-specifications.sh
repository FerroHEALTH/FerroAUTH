#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/ehdsi-specifications.sh
#
# Vendors the eHDSI documents the contact-point profile of the caller
# classification (#215) and the assertion check (#294) read into
# docs/specs/ehdsi-specifications/: the SAML Profile, Section II Security
# Services, the Service Location and Capability Lookup Profile, the NCPeH
# Components Specifications and the Messaging Profile 10.0.0, the
# Cryptographic Algorithms 9.0.0, the X.509 Certificates Profile 7.0.0 and
# the Interoperability Specifications 8.0.1. The owner retrieved them
# from the eHDSI wiki, which sits behind EU Login, so this script downloads
# nothing. The owner places the files in a local directory, and the script
# finds each one by the sha256 it pins (scripts/vendor/lib/pinned.sh, mode
# `supplied`) and commits it verbatim under a normalised name. The pins are
# the sha256 values FerroHEALTH/FerroFED's docs/specs/ehdsi-specifications/
# records for the same files.
#
# Each cover states distribution level PU and that reuse is authorised
# provided the source is acknowledged. The MyHealth@EU Requirements
# Catalogue 10.0.0 carries no such statement: it is pinned `withheld`, its
# sha256 is recorded, and no copy enters the repository or the cache.
#
# Usage:
#   scripts/vendor/ehdsi-specifications.sh DIR   commit the files DIR holds
#   scripts/vendor/ehdsi-specifications.sh --check
#                                                check the committed tree
#
# Requires: shasum, awk.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "${1:-}" in
  --check) export PINNED_CHECK=1 ;;
  '')
    if [ "${PINNED_DIGESTS_ONLY:-}" != "1" ]; then
      echo "usage: $0 DIR | --check" >&2
      exit 2
    fi
    ;;
  *)
    [ -d "$1" ] || {
      echo "$0: '$1' is not a directory" >&2
      exit 2
    }
    PINNED_SUPPLIED="$(cd "$1" && pwd)"
    export PINNED_SUPPLIED
    ;;
esac
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"
# shellcheck source=scripts/vendor/lib/pinned.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/pinned.sh"

corpus_require shasum awk
pinned_begin

wiki='https://webgate.ec.europa.eu/fpfis/wikis/display/EHDSI/2.+eHDSI+INTEROPERABILITY+SPECIFICATIONS%2C+Requirements+and+Frameworks'
reuse='"Reuse is authorised, provided the source is acknowledged." and "Distribution level*: PU", where "PU = Public" (the cover and control page, read 2026-11-05)'
docx_title='The docx core properties carry a stale title (dc:title "D3.7.2 Section I - Security Policies_v0.8"), so the sha256 identifies the file, not the metadata.'
pdf_title='The PDF document information carries a stale title ("D3.7.2 Section I - Security Policies_v0.8"), so the sha256 identifies the file, not the metadata.'
pdf_none='The PDF document information carries no title; the sha256 identifies the file.'

# ack SOURCE_LINE: the acknowledgement the cover names, quoted from its
# source line.
ack() { printf 'Acknowledgement: "Source: %s", the source line of the cover.' "$1"; }

pin supplied ehdsi-interoperability-specifications-8.0.1.docx \
  'eHDSI Interoperability Specifications, document version 8.0.1, 24/02/2025, status Wave 8 Operation Ready' \
  "$wiki" e4b79689176b8547ae0987f065ee0e1dce7734cb111b95c6fda75f33fd6230c1 "$reuse" \
  "$(ack 'DG SANTE, CEF eHealth DSI, 2025') The owner supplied eHDSI_Interoperability_Specifications_v8.0.1.docx. $docx_title"
pin supplied ehdsi-saml-profile-10.0.0.pdf \
  'SAML Profile, document version 10.0.0, 01/06/2026, status Wave 10 Operation Ready' \
  "$wiki" edd17e79b49ec56cd3799a58fd392ef51a09aa53c4bc726a05b4252dd7c2501d "$reuse" \
  "$(ack 'DG SANTE, MyHealth@EU, 2026') The owner supplied eHDSI_SAML_Profile_v10.0.0.pdf. $pdf_title"
pin supplied ehdsi-section-ii-security-services-10.0.0.pdf \
  'Section II – Security Services, document version 10.0.0, 01/06/2026, status Wave 10 Operation Ready' \
  "$wiki" 0faf5f8895b0b500ea4e3f46e5de21a3c048e4c38939989e73483ab763c7c06d "$reuse" \
  "$(ack 'DG SANTE, CEF eHealth DSI, 2026') The owner supplied eHDSI_Section_II-Security_Services_v10.0.0.pdf. $pdf_title"
pin supplied ehdsi-service-location-and-capability-lookup-profile-10.0.0.pdf \
  'Service Location and Capability Lookup Profile, document version 10.0.0, 01/06/2026, status Wave 10 Operation Ready' \
  "$wiki" 0b238368a81c5710a2578e3b4154aa34fec32ecd035b051af72d617b5ae5221a "$reuse" \
  "$(ack 'DG SANTE, CEF eHealth DSI, 2026') The owner supplied eHDSI_Service_Location_and_Capability_Lookup_Profile_v10.0.0.pdf. $pdf_title"
pin supplied ehdsi-ncpeh-components-specifications-10.0.0.pdf \
  'NCPeH Components Specifications, document version 10.0.0, 01/06/2026, status Wave 10 Operation Ready' \
  "$wiki" 5da44873fefdf3f9bb2a855d3d6c053990f8730a25a0b5ffe1ccfe75e0e73ba2 "$reuse" \
  "$(ack 'DG SANTE, CEF MyHealth@EU, 2026') The owner supplied eHDSI_NCPeH_Components_Specifications_v10.0.0.pdf. $pdf_title"
pin supplied ehdsi-messaging-profile-10.0.0.pdf \
  'eHDSI Messaging Profile, document version 10.0.0, 01/06/2026, status Wave 10 Operation Ready' \
  "$wiki" 4b9aa0c6dd383417eb4c90944bb04b895f6b4b4095b46393957ab9f6e34c7976 "$reuse" \
  "$(ack 'DG SANTE, MyHealth@EU, 2026') The owner supplied eHDSI_Messaging_Profile_v10.0.0.pdf. $pdf_title"
pin supplied ehdsi-x509-certificates-profile-7.0.0.pdf \
  'X.509 Certificates Profile (document name X.509 Certificate Profile), document version 7.0.0, 19/07/2023, status Wave 7 Operation Ready' \
  "$wiki" c17ac1cc60ca686a805306856259f92d53a23e15652041474cf2008d20d40548 "$reuse" \
  "$(ack 'DG SANTE, MyHealth@EU, 2023') The owner supplied eHDSI_X509_Certificates_Profile_v7.0.0.pdf. $pdf_none"
pin supplied ehdsi-cryptographic-algorithms-9.0.0.pdf \
  'Cryptographic Algorithms, document version 9.0.0, 04/06/2025, status Wave 9 Operation Ready' \
  "$wiki" 2b2cf3612649f69b2b1e3b68ef0b4924c8d75ce00b02808a4a19fb28f942f952 "$reuse" \
  "$(ack 'DG SANTE, CEF eHealth DSI, 2025') The owner supplied eHDSI_Cryptographic_Algorithms_v9.0.0.pdf. $pdf_none"
pin withheld myhealth-eu-requirements-catalogue-10.0.0.pdf \
  'MyHealth@EU Requirements Catalogue, version 10.0.0 OR, target release W10-Operation Ready, document status DONE, status date 06 Mar 2026' \
  'https://webgate.ec.europa.eu/fpfis/wikis/display/EHDSI/1.+MyHealth@EU+Requirements+Catalogue' \
  4743869bbd57564a81b567c86619523f73f2ff0fabfec9a12f78127fd128408a \
  'None stated: the export carries no reuse statement, no distribution level and no licence on its cover or anywhere in its text (read by FerroHEALTH/FerroFED in full on 2026-11-05)' \
  'The owner supplied eHDSI Requirements Catalogue v10.0.0 OR.pdf, a 438-page export of the wiki page (10005748 bytes), read under an EU Login reading grant. It stays privileged-access and is not committed or cached; the caller classification cites it by version, section and requirement id only (§1.25, requirements 01 and 01.02).'
pinned_corpus ehdsi-specifications "eHDSI specifications" \
  "the eHDSI specifications supplied by the owner" \
  "The eHDSI SAML Profile, Section II Security Services, the Service Location
and Capability Lookup Profile, the NCPeH Components Specifications and the
Messaging Profile 10.0.0, the Cryptographic Algorithms 9.0.0, the X.509
Certificates Profile 7.0.0, and the eHDSI Interoperability Specifications
8.0.1, retrieved by
the owner from the eHDSI wiki, which sits behind EU Login. Each cover states
distribution level PU (Public) and \"Reuse is authorised, provided the
source is acknowledged.\", so each is committed verbatim, as the owner
supplied it, with the source line of its cover as the acknowledgement.
DG SANTE, the Directorate-General for Health and Food Safety of the
European Commission, publishes them for MyHealth@EU. The files are the ones
FerroHEALTH/FerroFED vendors under the same names, identified by the same
sha256.

The MyHealth@EU Requirements Catalogue 10.0.0 states no reuse or
distribution terms. It is recorded here by version, date and sha256, and
no copy of it enters the repository or the cache." none \
  "the contact-point profile of the caller classification (#215: the
  issuer, the attributes, the authentication classes, the IdA and TRC
  lifetimes and the refusal names), vendored by #224, and the IdA and TRC
  check (#294: the enveloped signature, the algorithm floor, the seal
  certificate and the subject linkage)"

say "done"
