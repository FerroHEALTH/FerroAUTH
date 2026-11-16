#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/inferno-smart-test-kit.sh
#
# Vendors the server-facing part of the Inferno SMART App Launch test kit
# into docs/specs/inferno-smart-test-kit/: the SMART App Launch STU 2.2
# server suite, every test group it runs, the kit's extraction of the
# SMART App Launch 2.2.0 requirements with its coverage map, and the
# repository's LICENSE and NOTICE. FerroSMART's conformance lane runs this
# kit (#520), and the step-1 research maps each group to the build step
# that makes it pass (#513). The kit is pinned at the release tag the
# "Inferno SMART App Launch test kit" row of docs/VERSIONS.md names; a tag
# is mutable, so the script resolves it to a commit and records the commit.
#
# Redistribution: the repository's LICENSE is the Apache License 2.0, which
# permits reproducing and distributing the work unmodified with the licence
# and the NOTICE kept beside it. The script fails if it stops being
# Apache 2.0.
#
# Usage:
#   scripts/vendor/inferno-smart-test-kit.sh
#
# Requires: curl, shasum, jq, tar.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl shasum jq tar

dest="docs/specs/inferno-smart-test-kit"
lib="lib/smart_app_launch"
paths=(
  LICENSE
  NOTICE.md
  README.md
  "$lib/version.rb"
  "$lib/smart_stu2_2_suite.rb"
  "$lib/discovery_stu2_2_group.rb"
  "$lib/discovery_stu2_group.rb"
  "$lib/well_known_capabilities_stu2_test.rb"
  "$lib/standalone_launch_group.rb"
  "$lib/standalone_launch_group_stu2.rb"
  "$lib/standalone_launch_group_stu2_2.rb"
  "$lib/ehr_launch_group.rb"
  "$lib/ehr_launch_group_stu2.rb"
  "$lib/ehr_launch_group_stu2_2.rb"
  "$lib/openid_connect_group.rb"
  "$lib/openid_connect_group_stu2_2.rb"
  "$lib/token_refresh_group.rb"
  "$lib/token_refresh_stu2_group.rb"
  "$lib/token_introspection_group.rb"
  "$lib/token_introspection_group_stu2_2.rb"
  "$lib/token_introspection_access_token_group.rb"
  "$lib/token_introspection_access_token_group_stu2_2.rb"
  "$lib/token_introspection_request_group.rb"
  "$lib/token_introspection_response_group.rb"
  "$lib/backend_services_authorization_group.rb"
  "$lib/requirements/smart_app_launch_test_kit_requirements.csv"
  "$lib/requirements/generated/smart_stu2_2_requirements_coverage.csv"
)

pin="$(corpus_pin_cell "Inferno SMART App Launch test kit")"
repo="$(corpus_pin_repo "$pin")"
tag="$(corpus_pin_tag "$pin")"
commit="$(corpus_resolve_tag "$repo" "$tag")"
want="$(corpus_pin_commit "$pin")"
[ "$commit" = "$want" ] || die "tag $tag of $repo resolves to $commit, the pin records $want"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "$repo tag $tag resolves to $commit"
committed="$(corpus_commit_date "$repo" "$commit")"
[ -n "$committed" ] || die "cannot read the date of $commit"
src="$(corpus_fetch "$repo" "$commit" "$tmp")"
corpus_take "$src" "$tmp/out" "${paths[@]}"

grep -q 'Apache License' "$tmp/out/LICENSE" || die "LICENSE is not the Apache License"
grep -q 'Version 2.0, January 2004' "$tmp/out/LICENSE" || die "LICENSE is not version 2.0"

rm -rf "$dest"
mkdir -p "$dest"
cp -R "$tmp/out/." "$dest/"

files="$(corpus_file_count "$dest")"
digest="$(corpus_tree_digest "$dest")"
fetched="$(corpus_fetched)"

cat > "$dest/PROVENANCE.md" << PROV
<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the Inferno SMART App Launch test kit

Vendored verbatim by \`scripts/vendor/inferno-smart-test-kit.sh\`. Never
edit a file here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/$repo>
- Pin: tag \`$tag\`, which resolves to commit \`$commit\` ($committed)
- Fetched: $fetched, from the archive of the commit
- Upstream licence: the repository's \`LICENSE\`, the Apache License,
  Version 2.0, January 2004, vendored beside this file with its
  \`NOTICE.md\`. Its §4 permits reproducing and distributing copies of the
  work in any medium, with a copy of the licence and the NOTICE given to
  every recipient. The files are unmodified.
- Layout: the upstream paths, unchanged
- Files: $files
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$digest\`
- Read by: the FerroSMART step-1 research (#513) and the Inferno lane
  (#520), \`docs/architecture.md\` §13

## What is taken

- \`$lib/smart_stu2_2_suite.rb\`: the SMART App Launch STU 2.2 server
  suite (\`smart_stu2_2\`), with its Standalone Launch, EHR Launch,
  Backend Services and Token Introspection groups.
- The group and test files that suite runs, from the STU 1 bases the STU 2
  and STU 2.2 groups extend to the Backend Services group.
- \`$lib/requirements/smart_app_launch_test_kit_requirements.csv\`: the
  kit's extraction of each SHALL, SHOULD and MAY of SMART App Launch 2.0.0
  and 2.2.0 with its actor, and
  \`$lib/requirements/generated/smart_stu2_2_requirements_coverage.csv\`,
  which maps each 2.2.0 requirement to the tests that check it.

The client suites, the User Access Brands suite, the presets and the
execution scripts are not taken.
PROV

say "$files files, tree digest $digest"
say "done"
