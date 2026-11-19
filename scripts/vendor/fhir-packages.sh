#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/vendor/fhir-packages.sh
#
# Fetches the FHIR packages the Brands Bundle check reads beside the vendored
# SMART App Launch package (#602), after FerroHEALTH/FerroBRIDGE's
# scripts/vendor/profile-packages.sh. Each row of the "FHIR packages" table
# of docs/VERSIONS.md pins one package at one version by the registry's sha1
# and the tarball's sha256. The script downloads each pinned tarball from the
# FHIR package registry into the ignored
# docs/specs/fhir-packages/<package>#<version>/package.tgz, checks both
# digests, and keeps a tarball already there at its pin without a download.
# The validator reads the tarballs as they are; only each PROVENANCE.md is
# committed.
#
# The closure starts at the dependencies the SMART package's package.json
# declares. A package of FHIR R4 (its `fhirVersions` name 4.0.x, or none, as
# the core package's do not) brings its own dependencies; a package of
# another release is held without them, and its R4 edition, the same name
# with `.r4` at the same version, joins the closure in its place.
#
# Usage:
#   scripts/vendor/fhir-packages.sh            # fetch what is missing, verify every pin, check the closure
#   scripts/vendor/fhir-packages.sh --stamp    # fetch every pin and rewrite each PROVENANCE.md
#   scripts/vendor/fhir-packages.sh --check    # offline: every PROVENANCE.md at its pin, every fetched
#                                              # tarball at its sha256, no unpinned package, the closure
#                                              # complete and nothing pinned outside it
#   scripts/vendor/fhir-packages.sh --cache-key   # a CI cache key over the pins
#
# Requires: curl, jq, tar, shasum.
#
# No specification governs this file: FerroSMART's own design.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# shellcheck source=scripts/vendor/lib/corpus.sh
# shellcheck disable=SC1091 # shellcheck is not run with -x; the library is checked on its own
. "$root/scripts/vendor/lib/corpus.sh"

registry="https://packages.fhir.org"
dest="docs/specs/fhir-packages"
smart_manifest="docs/specs/smart-app-launch/package/package.json"

# The rows of the FHIR packages table, one per line as
# `<package>#<version> <sha1> <sha256>`.
pinned_rows() {
  awk -F'|' '
    /^## / { on = ($0 ~ /^## FHIR packages/); next }
    on && NF >= 4 && $2 ~ /^[[:space:]]*`/ {
      k = $2; v = $3
      gsub(/`/, "", k); gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
      gsub(/`/, "", v)
      n = split(v, t, /[[:space:]]+/)
      sha1 = ""; sha256 = ""
      for (i = 1; i < n; i++) {
        if (t[i] == "sha1") sha1 = t[i + 1]
        if (t[i] == "sha256") sha256 = t[i + 1]
      }
      print k " " sha1 " " sha256
    }
  ' docs/VERSIONS.md
}

# The value after `- <Label>:` in the PROVENANCE.md $1, backticks removed.
provenance_line() {
  awk -v label="- $2:" '
    index($0, label) == 1 {
      v = substr($0, length(label) + 1)
      gsub(/`/, "", v); gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      print v; exit
    }' "$1"
}

# The `dependencies` of the package.json on standard input, one
# `<package>#<version>` per line.
dependencies_of() {
  jq -r '.dependencies // {} | to_entries[] | "\(.key)#\(.value)"'
}

# The package.json of the fetched tarball of $1.
manifest_of() {
  tar -xzOf "$dest/$1/package.tgz" package/package.json
}

# Fetches the pin $1 (`<package>#<version> <sha1> <sha256>`) unless its
# tarball is already there at its sha256.
fetch() {
  local ref sha1 sha256 name version meta url file got
  read -r ref sha1 sha256 <<< "$1"
  name="${ref%%#*}"
  version="${ref#*#}"
  file="$dest/$ref/package.tgz"
  if [ -f "$file" ] && [ "$(corpus_sha256 "$file")" = "$sha256" ] && [ "${stamp:-0}" = 0 ]; then
    return 0
  fi
  meta="$(corpus_get "$registry/$name")" || die "cannot read the registry metadata of $name"
  [ "$(jq -r --arg v "$version" '.versions[$v].dist.shasum // empty' <<< "$meta")" = "$sha1" ] ||
    die "the registry's sha1 of $ref is not the pin $sha1"
  url="$(jq -r --arg v "$version" '.versions[$v].dist.tarball // empty' <<< "$meta")"
  [ -n "$url" ] || die "the registry lists no tarball of $ref"
  mkdir -p "$dest/$ref"
  corpus_download "$url" "$file.part" || die "download of $ref failed"
  got="$(corpus_sha1 "$file.part")"
  [ "$got" = "$sha1" ] || die "$ref downloaded with sha1 $got, the pin $sha1"
  got="$(corpus_sha256 "$file.part")"
  [ "$got" = "$sha256" ] || die "$ref downloaded with sha256 $got, the pin $sha256"
  mv "$file.part" "$file"
  [ "$(manifest_of "$ref" | jq -r '"\(.name)#\(.version)"')" = "$ref" ] ||
    die "the package.json of $ref names another package"
  say "fetched $ref"
}

# Writes the PROVENANCE.md of the pin $1 from its fetched tarball.
provenance() {
  local ref sha1 sha256 manifest
  read -r ref sha1 sha256 <<< "$1"
  manifest="$(manifest_of "$ref")"
  cat > "$dest/$ref/PROVENANCE.md" << PROV
<!-- This file describes vendored third-party material; the bytes it pins
     keep their upstream licence, not the licence of this repository. -->

# Provenance: $ref

Fetched at build time by \`scripts/vendor/fhir-packages.sh\` into
\`package.tgz\` beside this file, which is ignored and never committed.
Change the pin in docs/VERSIONS.md and run the script with \`--stamp\`.

- Package: \`${ref%%#*}\`
- Version: ${ref#*#}
- Source: <$registry/${ref%%#*}/${ref#*#}>
- Registry sha1: \`$sha1\`
- Tarball sha256: \`$sha256\`
- FHIR versions: $(jq -r '(.fhirVersions // ["4.0.1, the core package"]) | join(", ")' <<< "$manifest")
- Declared dependencies: $(jq -r '.dependencies // {} | to_entries | map("`\(.key)#\(.value)`") | if length == 0 then "none" else join(", ") end' <<< "$manifest")
- Author: $(jq -r '.author // "unstated"' <<< "$manifest")
- Fetched: $(corpus_fetched)
- Upstream licence: $(jq -r '.license // "unstated"' <<< "$manifest"), the \`license\` of \`package/package.json\`
PROV
}

# The dependencies the PROVENANCE.md of $1 records, one per line.
recorded_dependencies() {
  provenance_line "$dest/$1/PROVENANCE.md" "Declared dependencies" |
    tr ',' '\n' | tr -d ' ' | grep -v '^none$' | grep -v '^$' || true
}

# Whether the PROVENANCE.md of $1 records a package of FHIR R4.
recorded_r4() {
  local versions
  versions="$(provenance_line "$dest/$1/PROVENANCE.md" "FHIR versions")"
  [[ "$versions" == 4.0.* ]]
}

# Checks the closure from the SMART package over the PROVENANCE.md records:
# every package it reaches is pinned and every pin is reached.
closure() {
  local pins="$1" queue reached ref
  queue="$(dependencies_of < "$smart_manifest")"
  reached=""
  while [ -n "$queue" ]; do
    ref="$(head -n1 <<< "$queue")"
    queue="$(tail -n +2 <<< "$queue")"
    grep -qxF "$ref" <<< "$reached" && continue
    reached="$(printf '%s\n%s' "$reached" "$ref")"
    grep -qxF "$ref" <<< "$pins" || die "the closure reaches $ref, which docs/VERSIONS.md does not pin"
    [ -f "$dest/$ref/PROVENANCE.md" ] || die "$dest/$ref/PROVENANCE.md is missing"
    if recorded_r4 "$ref"; then
      queue="$(printf '%s\n%s' "$queue" "$(recorded_dependencies "$ref")")"
    else
      queue="$(printf '%s\n%s' "$queue" "${ref%%#*}.r4#${ref#*#}")"
    fi
    queue="$(grep -v '^$' <<< "$queue" || true)"
  done
  while read -r ref; do
    grep -qxF "$ref" <<< "$reached" || die "$ref is pinned and outside the closure"
  done <<< "$pins"
  say "the closure of the SMART package is complete: $(grep -c . <<< "$pins") packages"
}

# Checks every PROVENANCE.md against its pin, every fetched tarball against
# its sha256, and that no unpinned package is there.
check() {
  local rows="$1" ref sha1 sha256 file dir
  while read -r ref sha1 sha256; do
    file="$dest/$ref/PROVENANCE.md"
    [ -f "$file" ] || die "$file is missing"
    [ "$(provenance_line "$file" "Registry sha1")" = "$sha1" ] || die "$file records another sha1 than the pin"
    [ "$(provenance_line "$file" "Tarball sha256")" = "$sha256" ] || die "$file records another sha256 than the pin"
    if [ -f "$dest/$ref/package.tgz" ]; then
      [ "$(corpus_sha256 "$dest/$ref/package.tgz")" = "$sha256" ] ||
        die "$dest/$ref/package.tgz is not at its pin; run the script again"
    fi
  done <<< "$rows"
  for dir in "$dest"/*/; do
    [ -d "$dir" ] || continue
    ref="$(basename "$dir")"
    awk '{ print $1 }' <<< "$rows" | grep -qxF "$ref" || die "$dest/$ref is no pinned package"
  done
}

corpus_require jq tar shasum
rows="$(pinned_rows)"
[ -n "$rows" ] || die "docs/VERSIONS.md has no FHIR packages row"
pins="$(awk '{ print $1 }' <<< "$rows")"

case "${1:-}" in
  --cache-key)
    printf 'fhir-packages-%s\n' "$(printf '%s\n' "$rows" | shasum -a 256 | cut -d' ' -f1)"
    ;;
  --check)
    check "$rows"
    closure "$pins"
    ;;
  --stamp | "")
    corpus_require curl
    stamp=0
    [ "${1:-}" = "--stamp" ] && stamp=1
    while read -r row; do
      fetch "$row"
      if [ "$stamp" = 1 ]; then
        provenance "$row"
      fi
    done <<< "$rows"
    check "$rows"
    closure "$pins"
    ;;
  *)
    echo "usage: scripts/vendor/fhir-packages.sh [--stamp | --check | --cache-key]" >&2
    exit 2
    ;;
esac
