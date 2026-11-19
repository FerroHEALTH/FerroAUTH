#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/oidf-conformance-suite.sh
#
# Vendors the runner of the OpenID Foundation conformance suite into
# docs/specs/oidf-conformance-suite/: scripts/run-test-plan.py with the two
# modules it imports, and the repository's licence. The suite itself runs
# from its published image; the runner is not in that image, so the
# conformance lane (#621, scripts/oidf/lane.sh) runs this copy. Each file is
# pinned by the URL of the commit the release tag of the "OpenID Foundation
# conformance suite image" row names and by its sha256.
#
# Usage:
#   scripts/vendor/oidf-conformance-suite.sh [--check]
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
# shellcheck disable=SC1091 # as above
. "$root/scripts/vendor/lib/pinned.sh"

corpus_require curl shasum awk
pinned_begin

commit=23353b36957d6466010de767c812d2c91ed37638
raw="https://gitlab.com/openid/conformance-suite/-/raw/$commit"
version="release-v5.3.4, commit $commit"
mit='MIT: the repository'"'"'s LICENSE.txt, "This software is licensed under the MIT License: Copyright (c) 2019-2020 OpenID Foundation", vendored beside the files; it permits copying and distributing the software with the notice kept'

pin commit run-test-plan.py "$version" "$raw/scripts/run-test-plan.py" \
  6043f8fb9d64dcd30235540cae1f32eb4e94618d1fc5408f1e8ae626d6553ad2 "$mit" \
  'The runner: it creates a test plan at a suite, runs each module, and for a relying party module runs the client under test.'
pin commit conformance.py "$version" "$raw/scripts/conformance.py" \
  660214cc6ca9b3c09297f61908a575db7b1552e8f44eecd5740d1c27fa2cfca8 "$mit" \
  'The client of the suite API the runner imports.'
pin commit test_plan_parser.py "$version" "$raw/scripts/test_plan_parser.py" \
  2b00870b2dc46f1d44d047c715c0ef6978f24ece97a4a9d3b48ceeea8d01830f "$mit" \
  'The parser of the plan and variant syntax the runner imports.'
pin commit LICENSE.txt "$version" "$raw/LICENSE.txt" \
  23dbf079b6fbcbf171c15aa2db3ff19dfd00863156c24c6813d5fe9617426352 "$mit" \
  'The licence of the three files.'
pinned_corpus oidf-conformance-suite "OpenID Foundation conformance suite runner" \
  "the runner of the OpenID Foundation conformance suite" \
  "The runner script of the OpenID Foundation conformance suite
(<https://gitlab.com/openid/conformance-suite>) and the two Python modules it
imports, at the commit the release tag \`release-v5.3.4\` names, the release
whose image the lane runs. The files are executed unmodified and never read
as a specification." "" \
  "the OpenID Foundation conformance lane (#621, \`scripts/oidf/lane.sh\`)"

say "done"
