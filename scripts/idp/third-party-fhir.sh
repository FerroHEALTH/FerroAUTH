#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# FerroSMART's tokens at a third-party FHIR server behind a standard token
# validator (#598). HAPI FHIR, a FHIR server that is no FerroHEALTH product,
# sits behind Envoy's JWT authentication filter, which is given FerroSMART's
# issuer, its JWK Set URL and the audience and nothing else
# (app/ferrosmart/third-party/envoy.yaml; RFC 9068 §4). The lane shows that
# a Backend Services token and a person's token from a standalone launch
# through Keycloak each read a resource through the validator, and that a
# request without a token, a token for another audience and an expired token
# are refused.
#
# Envoy validates each token locally and never introspects, so it takes a
# revoked token until its `exp`. The lane therefore revokes a token and reads
# FerroSMART's introspection endpoint as a resource server that introspects
# would (RFC 7662 §2), which answers that the token is no longer active.
# Every image is a pin of docs/VERSIONS.md, and every secret is made for the
# run and never kept. No specification governs the check itself: our own
# design.
#
#   scripts/idp/third-party-fhir.sh
#
# It expects a built `target/debug/ferrosmart`, PostgreSQL at LANE_PG (a
# superuser URL without a database), docker, openssl, psql, jq, xxd and
# curl, and ports 8080, 8090, 8091 and 8180 free on the loopback interface.
# It writes its files and logs to LANE_DIR.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lane="$root/app/ferrosmart/third-party"
: "${LANE_PG:?the PostgreSQL URL}" "${LANE_DIR:?the run directory}"
mkdir -p "$LANE_DIR"

issuer=http://localhost:8080
base=http://localhost:8090/fhir
other=http://localhost:8099/fhir
client=third-party-lane

fail() {
  echo "third-party-fhir: $*" >&2
  exit 1
}

# The image the row ITEM of docs/VERSIONS.md pins by tag and digest.
pinned_image() {
  local image
  # shellcheck disable=SC2016 # the backticks are Markdown code spans of docs/VERSIONS.md, matched literally
  image=$(awk -F'|' -v item="$1" '$2 ~ "^ "item" $" { print $3 }' "$root/docs/VERSIONS.md" |
    grep -oE '`[^`]+@sha256:[0-9a-f]{64}`' | head -1 | tr -d '`' || true)
  [ -n "$image" ] || fail "no image pin for '$1' in docs/VERSIONS.md"
  printf '%s\n' "$image"
}

stop() {
  kill "${smart:-}" 2> /dev/null || true
  for name in ferrosmart-third-party-envoy ferrosmart-third-party-fhir ferrosmart-third-party-keycloak; do
    docker logs "$name" > "$LANE_DIR/$name.log" 2>&1 || true
    docker rm -f -v "$name" > /dev/null 2>&1 || true
  done
}
trap stop EXIT

fhir_user="$base/Practitioner/example"
password=$(openssl rand -hex 16)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$LANE_DIR/signing.pem" 2> /dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$LANE_DIR/assertion.pem" 2> /dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$LANE_DIR/client.pem" 2> /dev/null
modulus=$(openssl rsa -in "$LANE_DIR/client.pem" -noout -modulus | cut -d= -f2 | xxd -r -p |
  openssl base64 -A | tr '+/' '-_' | tr -d '=')
jq -n --arg n "$modulus" '{keys: [{kty: "RSA", kid: "lane", alg: "RS384", n: $n, e: "AQAB"}]}' \
  > "$LANE_DIR/client.jwks.json"
psql "$LANE_PG/postgres" -qc 'CREATE DATABASE ferrosmart_third_party'

# The FHIR server, on a port of its own behind the validator, and one
# synthetic patient written to it directly.
docker run -d --name ferrosmart-third-party-fhir --network host -e SERVER_PORT=8091 \
  "$(pinned_image 'HAPI FHIR server image')" > /dev/null
"$root/scripts/idp/keycloak-up.sh" ferrosmart-third-party-keycloak "$password" "$fhir_user"
for _ in $(seq 1 120); do
  curl -fsS -o /dev/null http://localhost:8091/fhir/metadata 2> /dev/null && break
  sleep 2
done
curl -fsS -o /dev/null -X PUT http://localhost:8091/fhir/Patient/example \
  -H 'Content-Type: application/fhir+json' \
  -d '{"resourceType":"Patient","id":"example","name":[{"family":"Example","given":["Synthetic"]}]}' ||
  fail "the FHIR server took no patient"

"$root/target/debug/ferrosmart" --config "$lane/ferrosmart.toml" \
  --set server.listen=127.0.0.1:8080 \
  --set "ferrosmart.keys.private_key_file=$LANE_DIR/signing.pem" \
  --set "ferrosmart.upstream.private_key_jwt.keys.private_key_file=$LANE_DIR/assertion.pem" \
  --set "ferrosmart.database.url=$LANE_PG/ferrosmart_third_party" \
  --set "ferrosmart.client[1].jwks_file=$LANE_DIR/client.jwks.json" \
  serve > "$LANE_DIR/ferrosmart-third-party.log" 2>&1 &
smart=$!
for _ in $(seq 1 30); do
  curl -fsS -o /dev/null "$issuer/.well-known/smart-configuration" && break
  sleep 1
done

# The validator, which reads FerroSMART's JWK Set on the first token.
docker run -d --name ferrosmart-third-party-envoy --network host \
  -v "$lane/envoy.yaml:/etc/envoy/envoy.yaml:ro" \
  "$(pinned_image 'Envoy token validator image')" -c /etc/envoy/envoy.yaml > /dev/null
for _ in $(seq 1 30); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$base/metadata")" = 401 ] && break
  sleep 1
done

# The lane client's assertion for the token endpoint (RFC 7523 §2.2).
assertion() { "$root/scripts/inferno/assertion.sh" "$LANE_DIR/client.pem" "$issuer/token" "$client"; }

# An access token of the lane's client for `scope` with the audience
# `resource`, by the client credentials grant (SMART App Launch 2.2.0,
# Backend Services).
backend_token() {
  curl -fsS "$issuer/token" \
    --data-urlencode grant_type=client_credentials --data-urlencode "scope=$1" \
    --data-urlencode "resource=$2" \
    --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
    --data-urlencode "client_assertion=$(assertion)" | jq -r .access_token
}

# The status the validator answers a read of the patient with, bearing
# `token` when it is given.
read_status() {
  if [ "$#" -eq 0 ]; then
    curl -s -o "$LANE_DIR/answer.json" -w '%{http_code}' "$base/Patient/example"
  else
    curl -s -o "$LANE_DIR/answer.json" -w '%{http_code}' -H "Authorization: Bearer $1" "$base/Patient/example"
  fi
}

# Fails unless the last answer is the synthetic patient.
is_patient() {
  [ "$(jq -r '.resourceType + "/" + .id' "$LANE_DIR/answer.json")" = Patient/example ] ||
    fail "$1 did not read the patient: $(head -c 200 "$LANE_DIR/answer.json")"
}

# 1. No token: refused (RFC 6750 §3.1).
status=$(read_status)
[ "$status" = 401 ] || fail "a request without a token answered $status, not 401"

# 2. A Backend Services token reads the resource.
token=$(backend_token system/Patient.rs "$base")
status=$(read_status "$token")
[ "$status" = 200 ] || fail "a Backend Services token answered $status, not 200"
is_patient "a Backend Services token"

# 3. A person's token from a standalone launch reads the resource.
answer=$(LAUNCH_USER=clinician LAUNCH_PASSWORD=$password \
  "$root/scripts/idp/standalone-launch.sh" keycloak "$issuer" example-app \
  http://localhost:9000/callback "$base" "openid fhirUser user/Patient.rs")
status=$(read_status "$(jq -r .access_token <<< "$answer")")
[ "$status" = 200 ] || fail "a person's token answered $status, not 200"
is_patient "a person's token"

# 4. A token for another audience is refused (RFC 9068 §4, `aud`).
status=$(read_status "$(backend_token system/Patient.rs "$other")")
case "$status" in 401 | 403) ;; *) fail "a token for another audience answered $status" ;; esac

# 5. A token past its `exp` is refused (RFC 9068 §4, RFC 7519 §4.1.4). The
#    lane's tokens live ten seconds and the validator allows one of skew.
token=$(backend_token system/Patient.rs "$base")
[ "$(read_status "$token")" = 200 ] || fail "the token to expire did not read the patient first"
sleep 13
status=$(read_status "$token")
[ "$status" = 401 ] || fail "an expired token answered $status, not 401"

# 6. A revoked token is no longer active at the introspection endpoint
#    (RFC 7009 §2.1, RFC 7662 §2.2), which is where a resource server that
#    introspects learns it. The caller presents a token of its own with the
#    scope `system/introspect` for FerroSMART as its audience.
introspect() {
  curl -fsS "$issuer/introspect" -H "Authorization: Bearer $2" --data-urlencode "token=$1" | jq -r .active
}
caller=$(backend_token system/introspect "$issuer")
token=$(backend_token system/Patient.rs "$base")
[ "$(introspect "$token" "$caller")" = true ] || fail "a fresh token is not active at the introspection endpoint"
curl -fsS -o /dev/null "$issuer/revoke" --data-urlencode "token=$token" \
  --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$(assertion)" || fail "the token could not be revoked"
[ "$(introspect "$token" "$caller")" = false ] || fail "a revoked token is still active at the introspection endpoint"

echo "third-party-fhir: HAPI FHIR behind Envoy took a Backend Services token and a person's token, and refused no token, another audience and an expired token"
