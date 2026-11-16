#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The Inferno lane's EHR: it registers a launch at FerroSMART's launch API for
# the kit's app and the FHIR server ISS (`POST /launch`, docs/architecture.md
# §13.6 item 3), authenticated as the lane's own client, and opens the app's
# launch URI with `iss` and `launch` as an EHR does (SMART App Launch 2.2.0,
# Launch App: EHR Launch). It runs where the kit's execution script runs, so
# it needs only bash, curl, openssl and sed; CURL_CA_BUNDLE names the lane's
# CA. No specification governs the script: our own design.
#
#   scripts/inferno/ehr-launch.sh LAUNCH_URI ISS
#
# LANE_KEY names the lane client's private key, SMART_ISSUER FerroSMART's
# issuer and LAUNCH_APP the app's client_id.
set -euo pipefail

[ "$#" -eq 2 ] || {
  echo "usage: scripts/inferno/ehr-launch.sh LAUNCH_URI ISS" >&2
  exit 2
}
launch_uri=$1 iss=$2
: "${LANE_KEY:?the key of the lane client}" "${SMART_ISSUER:?the issuer of FerroSMART}" "${LAUNCH_APP:?the client_id of the app}"

assertion=$("$(dirname "$0")/assertion.sh" "$LANE_KEY" "$SMART_ISSUER/token")
answer=$(curl -fsS "$SMART_ISSUER/launch" \
  --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$assertion" \
  --data-urlencode "app_client_id=$LAUNCH_APP" --data-urlencode "resource=$iss")
launch=$(sed -nE 's/.*"launch" *: *"([^"]+)".*/\1/p' <<< "$answer")
[ -n "$launch" ] || {
  echo "ehr-launch: FerroSMART registered no launch" >&2
  exit 1
}
curl -fsS -o /dev/null -G "$launch_uri" --data-urlencode "iss=$iss" --data-urlencode "launch=$launch"
