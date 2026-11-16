#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# A client assertion of the Inferno lane's own client (`inferno-lane`): a JWT
# signed RS384 with the key at KEY, `iss` and `sub` the client, `aud` the
# token endpoint, a `jti` used once and an `exp` four minutes ahead (RFC 7523
# §3; SMART App Launch 2.2.0, Client Authentication: Asymmetric, Request).
# It needs bash, openssl and date. No specification governs the script: our
# own design.
#
#   scripts/inferno/assertion.sh KEY TOKEN_ENDPOINT
set -euo pipefail

[ "$#" -eq 2 ] || {
  echo "usage: scripts/inferno/assertion.sh KEY TOKEN_ENDPOINT" >&2
  exit 2
}
key=$1 audience=$2

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

now=$(date +%s)
header=$(printf '{"alg":"RS384","typ":"JWT","kid":"lane"}' | b64url)
claims=$(printf '{"iss":"inferno-lane","sub":"inferno-lane","aud":"%s","iat":%d,"exp":%d,"jti":"%s"}' \
  "$audience" "$now" "$((now + 240))" "$(openssl rand -hex 16)" | b64url)
signature=$(printf '%s.%s' "$header" "$claims" | openssl dgst -sha384 -sign "$key" | b64url)
printf '%s.%s.%s\n' "$header" "$claims" "$signature"
