#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/smart-app-launch.sh
#
# Vendors SMART App Launch into docs/specs/smart-app-launch/: the published
# HL7 FHIR package `hl7.fhir.uv.smart-app-launch` at the version the
# "SMART App Launch package" row of docs/VERSIONS.md pins, verified against
# the registry's checksum, under package/; and the specification's page
# sources (input/pages/*.md, the includes they use and the two diagrams they
# embed) from the HL7/smart-app-launch repository at the commit the
# "SMART App Launch source" row pins, under repository/. The script proves
# the release tag still names that commit and that the commit predates the
# package build, so the pages are the ones the publication renders.
#
# Usage:
#   scripts/vendor/smart-app-launch.sh
#
# Requires: curl, tar, shasum, jq.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

corpus_require curl tar shasum jq

dest="docs/specs/smart-app-launch"
package="hl7.fhir.uv.smart-app-launch"
registry="https://packages.fhir.org"

package_pin="$(corpus_pin_cell "SMART App Launch package")"
version="$(awk '{ print $1; exit }' <<< "$package_pin")"
want_sha1="$(corpus_pin_field sha1 "$package_pin")"
case "$version" in
  *[!A-Za-z0-9.-]*) die "the package pin is not a plain version: '$version'" ;;
esac
grep -qE '^[0-9a-f]{40}$' <<< "$want_sha1" || die "the package pin names no sha1"

source_pin="$(corpus_pin_cell "SMART App Launch source")"
repo="$(corpus_pin_repo "$source_pin")"
tag="$(corpus_pin_field tag "$source_pin")"
commit="$(corpus_pin_commit "$source_pin")"
[ -n "$tag" ] || die "the source pin names no tag"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "package $package $version from $registry"
meta="$(corpus_get "$registry/$package")" || die "cannot read the registry metadata of $package"
registry_sha1="$(jq -r --arg v "$version" '.versions[$v].dist.shasum // empty' <<< "$meta")"
tarball="$(jq -r --arg v "$version" '.versions[$v].dist.tarball // empty' <<< "$meta")"
latest="$(jq -r '."dist-tags".latest // empty' <<< "$meta")"
[ -n "$registry_sha1" ] || die "the registry lists no version $version of $package"
say "the registry's latest is ${latest:-unstated}"
[ "$registry_sha1" = "$want_sha1" ] ||
  die "the registry records sha1 $registry_sha1 for $package $version, the pin $want_sha1"
[ -n "$tarball" ] || die "the registry lists no tarball for $package $version"
corpus_download "$tarball" "$tmp/package.tgz" || die "download of $package $version failed"
got_sha1="$(corpus_sha1 "$tmp/package.tgz")"
[ "$got_sha1" = "$want_sha1" ] || die "$package $version downloaded with sha1 $got_sha1, the pin $want_sha1"
package_sha256="$(corpus_sha256 "$tmp/package.tgz")"
mkdir -p "$tmp/x"
tar -xzf "$tmp/package.tgz" -C "$tmp/x"
[ -f "$tmp/x/package/package.json" ] || die "$package $version has no package/package.json"
declared="$(jq -r '.version // empty' "$tmp/x/package/package.json")"
[ "$declared" = "$version" ] || die "package.json declares version $declared, the pin $version"
licence="$(jq -r '.license // "unstated"' "$tmp/x/package/package.json")"
fhir_versions="$(jq -r '(.fhirVersions // []) | join(", ")' "$tmp/x/package/package.json")"
author="$(jq -r '.author // "unstated"' "$tmp/x/package/package.json")"
published="$(jq -r '.url // empty' "$tmp/x/package/package.json")"
canonical="$(jq -r '.canonical // empty' "$tmp/x/package/package.json")"
built="$(jq -r '.date // empty' "$tmp/x/package/package.json")"
grep -qE '^[0-9]{14}$' <<< "$built" || die "package.json carries no build date"
dependencies="$(jq -r '.dependencies // {} | to_entries | map("`\(.key)` \(.value)") | join(", ")' "$tmp/x/package/package.json")"

say "source $repo tag $tag at $commit"
resolved="$(corpus_resolve_tag "$repo" "$tag")"
[ "$resolved" = "$commit" ] || die "tag $tag of $repo now names $resolved, the pin $commit"
committed="$(corpus_commit_date "$repo" "$commit")"
[ -n "$committed" ] || die "cannot read the date of $commit"
# The pages are the publication's only when they predate the package build.
committed_compact="$(tr -d ':TZ-' <<< "$committed")"
[ "$committed_compact" \< "$built" ] ||
  die "commit $commit ($committed) is later than the package build $built"
mkdir -p "$tmp/spec"
spec_root="$(corpus_fetch "$repo" "$commit" "$tmp/spec")"
[ ! -e "$spec_root/LICENSE" ] || die "$repo now carries a LICENSE file; vendor it and record it"

rm -rf "$dest"
mkdir -p "$dest/repository"
mv "$tmp/x/package" "$dest/package"
corpus_take "$spec_root" "$dest/repository" \
  README.md \
  input/pages \
  input/includes \
  input/images/clinical-scope-syntax-diagram.png \
  input/images/backend-service-authorization-diagram.png

pages="$(find "$dest/repository/input/pages" -type f -name '*.md' | wc -l | tr -d '[:space:]')"
stray="$(find "$dest/repository/input/pages" -type f ! -name '*.md' | head -n1)"
[ -z "$stray" ] || die "input/pages carries a non-markdown file: ${stray#"$dest/"}"
for page in scopes-and-launch-context app-launch backend-services conformance \
  client-confidential-asymmetric client-confidential-symmetric token-introspection; do
  [ -s "$dest/repository/input/pages/$page.md" ] || die "the source carries no page $page.md"
done

package_files="$(corpus_file_count "$dest/package")"
package_digest="$(corpus_tree_digest "$dest/package")"
repository_files="$(corpus_file_count "$dest/repository")"
repository_digest="$(corpus_tree_digest "$dest/repository")"
fetched="$(corpus_fetched)"

cat > "$dest/PROVENANCE.md" << PROV
<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: SMART App Launch $version

Vendored verbatim by \`scripts/vendor/smart-app-launch.sh\`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Version: $version
- Publication: <$published> (canonical \`$canonical\`), the
  edition the package and the page sources below belong to
- FHIR versions: $fhir_versions
- Author: $author
- Fetched: $fetched
- Upstream licence: $licence, the \`license\` of \`package/package.json\`
  (Creative Commons Attribution 4.0 International,
  <https://creativecommons.org/licenses/by/4.0/>), which permits copying and
  redistribution in any medium with attribution. The repository carries no
  \`LICENSE\` file at the pinned commit, so the package's declaration is the
  one statement and this file is the attribution: SMART App Launch
  $version by $author, licensed CC BY 4.0, vendored unchanged.

## package/

The FHIR package \`$package\` $version from the FHIR package registry
(<$registry/$package>), extracted at its own layout.

- Registry sha1: \`$registry_sha1\` (the registry's \`dist.shasum\`,
  verified on the downloaded tarball)
- Tarball sha256: \`$package_sha256\`
- Built: $built (\`package.json\` \`date\`)
- Declared dependencies: $dependencies
- Files: $package_files
- Package tree digest (sha256 over the sorted per-file \`sha256  path\`
  listing): \`$package_digest\`

It carries the ImplementationGuide resource, the CapabilityStatement, the
StructureDefinitions, the ValueSets and the CodeSystem the guide defines,
with its examples; the guide's prose is not in the package, which is why the
page sources are vendored beside it.

## repository/

The page sources of the guide from <https://github.com/$repo> at tag
\`$tag\`, resolved to commit \`$commit\` ($committed), which predates the
package build, so these are the sources the publication renders. Each
\`input/pages/<name>.md\` renders as \`<name>.html\` under the publication
URL above.

- Pin: commit \`$commit\`
- Files: $repository_files, of which $pages are \`input/pages/*.md\`
- Repository tree digest (sha256 over the sorted per-file \`sha256  path\`
  listing): \`$repository_digest\`

The pages the design cites: \`scopes-and-launch-context.md\` (the scope
grammar and the launch context), \`app-launch.md\` (the launch flows and the
token request), \`backend-services.md\` (the client-credentials grant with a
signed assertion), \`client-confidential-asymmetric.md\` and
\`client-confidential-symmetric.md\` (client authentication),
\`conformance.md\` (the capability sets and the
\`.well-known/smart-configuration\` document) and \`token-introspection.md\`.
PROV

say "package $package_files files, digest $package_digest"
say "repository $repository_files files ($pages pages), digest $repository_digest"
say "done"
