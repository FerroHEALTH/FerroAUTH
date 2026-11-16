#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# A SMART standalone launch through FerroSMART and an upstream provider's
# login form, as a browser without script would make it, ending in the
# token response (SMART App Launch 2.2.0, App Launch: Launch App: Standalone
# Launch, Obtain authorization code, Obtain access token). The examples of
# #522 and #523 run it in CI. No specification governs the driver: our own
# design.
#
#   scripts/idp/standalone-launch.sh LOGIN <issuer> <client_id> <redirect_uri> <aud> <scope>
#
# LOGIN names how the provider's login form is answered: `keycloak` posts the
# username and password to the form `kc-form-login` names. The person is
# read from LAUNCH_USER and LAUNCH_PASSWORD. It prints the token response
# and fails on any step that does not answer as the specification says.
set -euo pipefail

[ "$#" -eq 6 ] || {
  echo "usage: scripts/idp/standalone-launch.sh LOGIN <issuer> <client_id> <redirect_uri> <aud> <scope>" >&2
  exit 2
}
login=$1 issuer=$2 client_id=$3 redirect_uri=$4 aud=$5 scope=$6
: "${LAUNCH_USER:?the person to log in as}" "${LAUNCH_PASSWORD:?their password}"

fail() {
  echo "standalone-launch: $*" >&2
  exit 1
}

# A form-urlencoded value (RFC 3986 §2.1), with jq's @uri.
enc() { jq -rn --arg value "$1" '$value | @uri'; }

# The query parameter `name` of the URL `url`, decoded.
param() {
  local value
  value=$(tr "&" "\n" <<< "${2#*\?}" | sed -n "s/^$1=//p" | head -1)
  value=${value//+/ }
  printf "%b" "${value//%/\\x}"
}

verifier=$(openssl rand -hex 32)
challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
state=$(openssl rand -hex 16)

# 1. The app sends the browser to FerroSMART's authorization endpoint.
config=$(curl -fsS "$issuer/.well-known/smart-configuration")
authorize=$(jq -r .authorization_endpoint <<< "$config")
token_endpoint=$(jq -r .token_endpoint <<< "$config")
at="$authorize?response_type=code&client_id=$(enc "$client_id")&redirect_uri=$(enc "$redirect_uri")"
at="$at&scope=$(enc "$scope")&state=$state&aud=$(enc "$aud")&code_challenge=$challenge&code_challenge_method=S256"

# 2. The person logs in and consents (scripts/idp/authorize.sh).
location=$("$(dirname "$0")/authorize.sh" "$login" "$at")

# 3. FerroSMART redirects to the app with the code, the state as sent and
#    its issuer (RFC 6749 §4.1.2; RFC 9207 §2).
case "$location" in "$redirect_uri"\?*) ;; *) fail "the consent did not return to the app: $location" ;; esac
[ "$(param state "$location")" = "$state" ] || fail "the state came back changed"
[ "$(param iss "$location")" = "$issuer" ] || fail "the response names another issuer"
code=$(param code "$location")
[ -n "$code" ] || fail "the response carries no code: $(param error "$location")"

# 4. The app redeems the code (RFC 6749 §4.1.3; RFC 7636 §4.5).
curl -fsS "$token_endpoint" \
  --data-urlencode grant_type=authorization_code --data-urlencode "code=$code" \
  --data-urlencode "redirect_uri=$redirect_uri" --data-urlencode "client_id=$client_id" \
  --data-urlencode "code_verifier=$verifier"
