#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# Installs the browser FerroSMART's screenshot capture drives, Chrome for
# Testing and its matching chromedriver, at one pinned release, each zip
# checked against its pinned SHA-256 before it is unpacked (no specification
# governs this: our own design, after FerroHEALTH/FerroPIX's script of the
# same name).
#
# The download URLs come from the Chrome for Testing JSON API, for the one
# pinned version and this platform. The version and digests below are the
# rows of docs/VERSIONS.md, which scripts/checks/versions.sh holds them to.
# The capture reads DIR at target/journey-tools unless
# FERROSMART_CHROMEDRIVER and FERROSMART_CHROME name other binaries.
#
# Usage:
#   scripts/release/journey-tools.sh DIR   install both into DIR, as
#                                          DIR/chrome-<platform>/ and
#                                          DIR/chromedriver-<platform>/
set -Eeuo pipefail

chrome_version="157.0.8103.38"
chrome_linux64_sha256="8cdeb344e9b2cefe59f4aea8d1d93d5d93054c03cde217665c16fc1f62e72a66"
chrome_mac_arm64_sha256="3406b38b52b7d341d74450eb7b369be038c9fec9894c8b8a9e9e9f97333caf2f"
chromedriver_linux64_sha256="329525fa0bf02be19794de1e9475772ef64695e0456f142888bd70df3147dc1e"
chromedriver_mac_arm64_sha256="e59394fda6a05067362c225678e185e46e473cebea1593025deb2b2641b75688"

api="https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json"

die() {
  echo "journey-tools: $*" >&2
  exit 1
}

# Prints the SHA-256 of FILE, with the tool the platform has.
digest_of() {
  local file="$1"
  if command -v sha256sum > /dev/null; then
    sha256sum "$file" | cut -d' ' -f1
  else
    shasum -a 256 "$file" | cut -d' ' -f1
  fi
}

# Checks FILE against the SHA-256 DIGEST.
verify() {
  local file="$1" digest="$2" found
  found="$(digest_of "$file")"
  [[ "$found" = "$digest" ]] || die "$file has SHA-256 $found, the pin is $digest"
}

# Downloads URL into FILE.
fetch() {
  local url="$1" file="$2"
  curl --fail --silent --show-error --location --retry 3 --output "$file" "$url"
}

# Prints the URL the API lists for the pinned version of PRODUCT (chrome or
# chromedriver) on PLATFORM, from the API answer in FILE.
url_of() {
  local product="$1" platform="$2" answer="$3"
  jq -r --arg version "$chrome_version" --arg product "$product" --arg platform "$platform" \
    '.versions[] | select(.version == $version) | .downloads[$product][]?
      | select(.platform == $platform) | .url' "$answer"
}

# Fetches PRODUCT for PLATFORM into DIR, checks it against DIGEST, and
# unpacks it over an earlier copy.
install_one() {
  local product="$1" platform="$2" digest="$3" dir="$4" url zip
  url="$(url_of "$product" "$platform" "$dir/download/versions.json")"
  [[ -n "$url" ]] || die "the Chrome for Testing API lists no $product $chrome_version for $platform"
  zip="$dir/download/$product-$platform.zip"
  fetch "$url" "$zip"
  verify "$zip" "$digest"
  unzip -q -o "$zip" -d "$dir"
}

install() {
  local dir="$1" platform chrome_sha driver_sha chrome said
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)
      platform="linux64"
      chrome_sha="$chrome_linux64_sha256"
      driver_sha="$chromedriver_linux64_sha256"
      chrome="$dir/chrome-linux64/chrome"
      ;;
    Darwin-arm64)
      platform="mac-arm64"
      chrome_sha="$chrome_mac_arm64_sha256"
      driver_sha="$chromedriver_mac_arm64_sha256"
      chrome="$dir/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
      ;;
    *) die "no pinned digest for $(uname -s) $(uname -m); install Chrome for Testing $chrome_version by hand" ;;
  esac
  command -v jq > /dev/null || die "jq reads the Chrome for Testing API; install it first"
  command -v unzip > /dev/null || die "unzip unpacks the downloads; install it first"
  mkdir -p "$dir/download"
  fetch "$api" "$dir/download/versions.json"
  install_one chrome "$platform" "$chrome_sha" "$dir"
  install_one chromedriver "$platform" "$driver_sha" "$dir"
  said="$("$dir/chromedriver-$platform/chromedriver" --version)"
  case "$said" in
    *"ChromeDriver $chrome_version "*) ;;
    *) die "the unpacked chromedriver says '$said', not $chrome_version" ;;
  esac
  [[ -x "$chrome" ]] || die "the Chrome zip holds no $chrome"
  echo "journey-tools: Chrome for Testing and chromedriver $chrome_version are in $dir"
}

case "${1:-}" in
  "" | -*)
    echo "usage: scripts/release/journey-tools.sh DIR" >&2
    exit 2
    ;;
  *)
    mkdir -p "$1"
    install "$(cd "$1" && pwd)"
    ;;
esac
