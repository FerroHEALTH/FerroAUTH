#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/ihe-balp-pages.sh
#
# Vendors the Volume 3 content page of the IHE Basic Audit Log Patterns
# (BALP) 1.1.4 into docs/specs/ihe-balp-pages/, as profiles.ihe.net renders
# it. Its 3:5.7.6 "Consent Authorized Decision Audit Message" is the consent
# decision record whose Consent entity the federation field
# `consent.reference` carries to a product (#286). The page is pinned by its
# versioned URL and sha256 (scripts/vendor/lib/pinned.sh), the bytes
# FerroHEALTH/FerroAUDIT and FerroHEALTH/FerroFED vendor under the same
# directory name. The implementation guide is licensed CC-BY-4.0 by its
# ImplementationGuide resource, and the page footer links the licence of IHE
# General Introduction §9.
#
# Usage:
#   scripts/vendor/ihe-balp-pages.sh           fetch and write the tree
#   scripts/vendor/ihe-balp-pages.sh --check   check the committed tree, offline
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

balp='CC-BY-4.0: the license of the ImplementationGuide resource of ihe.iti.balp 1.1.4; the page footer links IHE General Introduction §9 (https://profiles.ihe.net/GeneralIntro/ch-9.html)'

pin commit content.html "BALP 1.1.4, 3:5.7" \
  https://profiles.ihe.net/ITI/BALP/1.1.4/content.html \
  a3c220e25086f97941544d9919ea521a63126023d66c27bfcd5e2e7ed17f9d09 "$balp" \
  'The Volume 3 content page; 3:5.7.6 "Consent Authorized Decision Audit Message" records an authorization decision based on a Consent, whose AuditEvent names the Consent as an entity.'
pinned_corpus ihe-balp-pages "IHE BALP narrative pages" \
  "the IHE BALP 1.1.4 content page" \
  "The Volume 3 content page (3:5.7) of the Basic Audit Log Patterns 1.1.4
implementation guide, committed under CC-BY-4.0. Attribution: IHE
International, IT Infrastructure Technical Committee, *Basic Audit Log
Patterns (BALP)* 1.1.4." "" \
  "the federation field \`consent.reference\` (#286, 3:5.7.6, the consent
  decision record)"

say "done"
