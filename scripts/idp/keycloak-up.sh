#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# Starts Keycloak for a lane: the image docs/VERSIONS.md pins, importing
# app/ferrosmart/examples/keycloak/ferrosmart-realm.json for a FerroSMART at
# http://localhost:8080, on port 8180 of the loopback interface, and waits
# until the realm answers. The lanes of #522 and #598 start their provider
# with it. No specification governs the script: our own design.
#
#   scripts/idp/keycloak-up.sh NAME PASSWORD FHIR_USER
#
# NAME is the container's name, which the caller removes; PASSWORD the
# password of the realm's one person, `clinician`; FHIR_USER the `fhirUser`
# the realm maps for them. It expects docker and curl, and writes the
# container's log to LANE_DIR/keycloak.log.
set -euo pipefail

[ "$#" -eq 3 ] || {
  echo "usage: scripts/idp/keycloak-up.sh NAME PASSWORD FHIR_USER" >&2
  exit 2
}
name=$1 password=$2 fhir_user=$3
: "${LANE_DIR:?the run directory}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
example="$root/app/ferrosmart/examples/keycloak"

# shellcheck disable=SC2016 # the backticks are Markdown code spans of docs/VERSIONS.md, matched literally
image=$(grep -E '^\| Keycloak test image \|' "$root/docs/VERSIONS.md" |
  sed -E 's/.*`(quay\.io\/keycloak\/keycloak:[^`]+)`, index digest `(sha256:[0-9a-f]{64})`.*/\1@\2/')
case "$image" in quay.io/keycloak/keycloak:*@sha256:*) ;; *)
  echo "keycloak-up: no Keycloak image pin in docs/VERSIONS.md" >&2
  exit 1
  ;;
esac

# NOTE: Keycloak's server guide, Importing and exporting realms, Using Environment Variables
# within the Realm Configuration Files: each placeholder of the realm reads the environment.
docker run -d --name "$name" --network host \
  -v "$example/ferrosmart-realm.json:/opt/keycloak/data/import/ferrosmart-realm.json:ro" \
  -e KC_HTTP_PORT=8180 -e KC_HTTP_HOST=127.0.0.1 \
  -e FERROSMART_KEYCLOAK_JWKS_URL=http://localhost:8080/upstream-jwks \
  -e FERROSMART_KEYCLOAK_REDIRECT_URI=http://localhost:8080/callback \
  -e "FERROSMART_KEYCLOAK_USER_PASSWORD=$password" \
  -e "FERROSMART_KEYCLOAK_FHIR_USER=$fhir_user" \
  "$image" start-dev --import-realm > /dev/null
for _ in $(seq 1 90); do
  curl -fsS -o /dev/null http://localhost:8180/realms/ferrosmart/.well-known/openid-configuration && break
  sleep 2
done
docker logs "$name" > "$LANE_DIR/keycloak.log" 2>&1
