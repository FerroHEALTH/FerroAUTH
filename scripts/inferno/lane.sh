#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The Inferno SMART App Launch lane (#520, docs/architecture.md §13.13):
# FerroSMART, FerroEHR as the resource server and the Inferno SMART App
# Launch test kit on one host network, the kit's STU 2.2 suite run by
# `inferno execute_script` over app/ferrosmart/inferno/smart_stu2_2.yaml.
# No specification governs the lane itself: our own design.
#
#   scripts/inferno/lane.sh check     the expected results hold every test to
#                                     `pass` outside exceptions.tsv
#   scripts/inferno/lane.sh run       start everything, run the suite, record
#                                     the results and list the pending groups
#
# `run` expects, as the `nextest (core and axum)` job of ci.yml provides
# them: a built `target/debug/ferrosmart`; the kit checked out at the
# pinned commit in INFERNO_KIT; PostgreSQL at
# LANE_PG (a superuser URL without a database); docker, openssl, psql, jq
# and curl; and sudo for the two /etc/hosts names. It writes its files and
# the logs to LANE_DIR.
# shellcheck disable=SC2016 # every backtick in a pattern or a format is a Markdown code span, matched or written literally
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lane="$root/app/ferrosmart/inferno"
versions="$root/docs/VERSIONS.md"

# The image a row of docs/VERSIONS.md pins, by its item name.
pinned_image() {
  local image
  image=$(awk -F'|' -v item="$1" '$2 ~ "^ "item" $" { print $3 }' "$versions" |
    grep -oE '`[^`]+@sha256:[0-9a-f]{64}`' | head -1 | tr -d '`')
  [ -n "$image" ] || { echo "lane: no image pin for '$1' in docs/VERSIONS.md" >&2; exit 1; }
  printf '%s\n' "$image"
}

# The rows of a table under app/ferrosmart/inferno, without its comments.
rows() {
  grep -vE '^(#|$)' "$lane/$1"
}

# Whether every issue of a comma-separated list is closed; `gh` unreadable
# counts as open.
all_closed() {
  local number
  for number in ${1//,/ }; do
    [ "$(gh issue view "$number" --json state --jq .state 2> /dev/null || true)" = CLOSED ] || return 1
  done
}

check() {
  local expected="$lane/smart_stu2_2_expected.json" failures=0 id result
  while IFS=$'\t' read -r id result; do
    if rows exceptions.tsv | cut -f1 | grep -qxF "$id"; then
      continue
    fi
    if [ "$result" != pass ]; then
      echo "lane: $id is expected to be '$result'; every test outside exceptions.tsv passes" >&2
      failures=$((failures + 1))
    fi
  done < <(jq -r '.[] | select(.test_id) | [.test_id, .result] | @tsv' "$expected")
  while IFS= read -r id; do
    if ! jq -e --arg id "$id" 'any(.[]; .test_id == $id and .result != "pass")' "$expected" > /dev/null; then
      echo "lane: exceptions.tsv lists $id, which the expected results do not hold failing" >&2
      failures=$((failures + 1))
    fi
  done < <(rows exceptions.tsv | cut -f1)
  [ "$failures" -eq 0 ] || exit 1
  echo "lane: the expected results pass every test outside exceptions.tsv"
}

# Every group not run and every test excepted, in the log and the job
# summary, with a warning once the issues a row waits on are closed.
pending() {
  local short id state issues needs kind reason
  local summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
  printf '### Inferno groups not run\n\n| Group | Waits on | Needs |\n|---|---|---|\n' >> "$summary"
  while IFS=$'\t' read -r short id state issues needs; do
    [ "$state" = pending ] || continue
    echo "lane: group $short ($id) is pending on #${issues//,/, #}: $needs"
    printf '| %s `%s` | #%s | %s |\n' "$short" "$id" "${issues//,/, #}" "$needs" >> "$summary"
    if all_closed "$issues"; then
      echo "::warning title=Inferno group $short can run::the issues group $short waits on are closed; add its step to smart_stu2_2.yaml and mark it run in groups.tsv"
    fi
  done < <(rows groups.tsv)
  printf '\n### Inferno tests excepted\n\n| Test | Kind | Issue | Reason |\n|---|---|---|---|\n' >> "$summary"
  while IFS=$'\t' read -r id kind issues reason; do
    echo "lane: test $id is excepted ($kind${issues:+, #$issues}): $reason"
    printf '| `%s` | %s | %s | %s |\n' "$id" "$kind" "$issues" "$reason" >> "$summary"
    if [ "$kind" = pending ] && all_closed "$issues"; then
      echo "::warning title=Inferno test excepted past its issue::#$issues is closed; record the new result of $id in smart_stu2_2_expected.json and drop its row from exceptions.tsv"
    fi
  done < <(rows exceptions.tsv)
}

# Each result of the session against the SMART App Launch 2.2.0
# requirements the kit's coverage map ties the test to.
record() {
  local results=$1
  local coverage="$root/docs/specs/inferno-smart-test-kit/lib/smart_app_launch/requirements/generated/smart_stu2_2_requirements_coverage.csv"
  {
    echo "### Inferno results against the SMART App Launch 2.2.0 requirements"
    echo
    echo "| Test | Result | Requirements |"
    echo "|---|---|---|"
    jq -r '.[] | select(.test_id) | [.test_id, .result] | @tsv' "$results" |
      while IFS=$'\t' read -r id result; do
        local requirements
        requirements=$(grep -F "$id" "$coverage" | cut -d, -f2 | sort -n | paste -sd, - || true)
        printf '| `%s` | %s | %s |\n' "$id" "$result" "${requirements:--}"
      done
  } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
}

wait_for() {
  local what=$1 url=$2
  for _ in $(seq 1 60); do
    if curl -fsS --cacert "$LANE_DIR/ca.crt" -o /dev/null "$url"; then
      return 0
    fi
    sleep 2
  done
  echo "lane: $what did not answer at $url" >&2
  return 1
}

# The development CA, the two server certificates and FerroSMART's signing
# key, made for this run and never kept.
make_keys() {
  local dir=$1 name
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj '/CN=FerroSMART Inferno lane CA' -keyout "$dir/ca.key" -out "$dir/ca.crt" 2> /dev/null
  for name in smart ehr; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -subj "/CN=$name.localhost" -keyout "$dir/$name.key" -out "$dir/$name.csr" 2> /dev/null
    printf 'subjectAltName=DNS:%s.localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' "$name" > "$dir/$name.ext"
    openssl x509 -req -in "$dir/$name.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
      -days 1 -extfile "$dir/$name.ext" -out "$dir/$name.crt" 2> /dev/null
  done
  rm -f "$dir/ca.key"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/signing.pem" 2> /dev/null
  # The public half of the kit's verification keys, its registered JWK Set.
  jq '{keys: [.keys[] | select(.key_ops | index("verify"))
        | {kty, kid, alg, crv, x, y, n, e} | with_entries(select(.value != null))]}' \
    "$INFERNO_KIT/lib/smart_app_launch/smart_jwks.json" > "$dir/inferno-client.jwks.json"
  chmod 0644 "$dir"/*.key "$dir/signing.pem"
}

run() {
  : "${INFERNO_KIT:?the kit checkout}" "${LANE_PG:?the PostgreSQL URL}" "${LANE_DIR:?the lane directory}"
  mkdir -p "$LANE_DIR"
  check
  make_keys "$LANE_DIR"
  echo '127.0.0.1 smart.localhost ehr.localhost' | sudo tee -a /etc/hosts > /dev/null
  psql "$LANE_PG/postgres" -qc 'CREATE DATABASE ferrosmart' -c 'CREATE DATABASE ferroehr'

  "$root/target/debug/ferrosmart" --config "$lane/ferrosmart.toml" \
    --set "server.tls.certificate_file=$LANE_DIR/smart.crt" \
    --set "server.tls.key_file=$LANE_DIR/smart.key" \
    --set "ferrosmart.keys.private_key_file=$LANE_DIR/signing.pem" \
    --set "ferrosmart.database.url=$LANE_PG/ferrosmart" \
    --set "ferrosmart.client[0].jwks_file=$LANE_DIR/inferno-client.jwks.json" \
    serve > "$LANE_DIR/ferrosmart.log" 2>&1 &
  wait_for FerroSMART https://smart.localhost:8443/.well-known/smart-configuration

  docker run -d --name inferno-lane-redis --network host "$(pinned_image 'Redis test image')" > /dev/null
  docker run -d --name inferno-lane-ferroehr --network host \
    -v "$lane/ferroehr.toml:/etc/ferroehr/ferroehr.toml:ro" -v "$LANE_DIR:/lane:ro" \
    -e FERROEHR_CONFIG=/etc/ferroehr/ferroehr.toml \
    -e "FERROEHR__DATABASE__URL=$LANE_PG/ferroehr" \
    -e FERROEHR__AUTH__TLS__TRUST_ROOTS_FILE=/lane/ca.crt \
    -e FERROEHR__SERVER__TLS__CERTIFICATE_FILE=/lane/ehr.crt \
    -e FERROEHR__SERVER__TLS__KEY_FILE=/lane/ehr.key \
    --add-host smart.localhost:127.0.0.1 --add-host ehr.localhost:127.0.0.1 \
    -e FERROEHR__USAGE_REPORT__ENABLED=false \
    "$(pinned_image 'FerroEHR resource server image')" > /dev/null
  wait_for FerroEHR https://ehr.localhost:9443/ferroehr/rest/.well-known/smart-configuration

  # The kit runs in the Ruby image docs/VERSIONS.md pins, on the gems its
  # Gemfile.lock locks, trusting the lane's CA beside the system roots.
  docker run -d --name inferno-lane-kit --network host \
    -v "$INFERNO_KIT:/kit" -v "$lane:/script" -v "$LANE_DIR:/lane:ro" -w /kit \
    -e APP_ENV=development -e SSL_CERT_FILE=/tmp/trust.pem \
    --add-host smart.localhost:127.0.0.1 --add-host ehr.localhost:127.0.0.1 \
    "$(pinned_image 'Inferno runtime')" sh -c '
      cat /etc/ssl/certs/ca-certificates.crt /lane/ca.crt > /tmp/trust.pem &&
      bundle install --quiet && bundle exec inferno migrate &&
      { bundle exec sidekiq -r ./worker.rb > /tmp/worker.log 2>&1 & } &&
      exec bundle exec puma' > /dev/null
  for _ in $(seq 1 150); do
    curl -fsS -o /dev/null http://localhost:4567 && break
    sleep 2
  done
  docker exec inferno-lane-kit bundle exec inferno execute_script /script/smart_stu2_2.yaml \
    2> "$LANE_DIR/execute.log" && status=0 || status=$?
  cat "$LANE_DIR/execute.log"
  docker logs inferno-lane-kit > "$LANE_DIR/inferno.log" 2>&1
  local session
  session=$(grep -oE 'Session created: [A-Za-z0-9_-]+' "$LANE_DIR/execute.log" | head -1 | cut -d' ' -f3 || true)
  if [ -n "$session" ]; then
    docker exec inferno-lane-kit bundle exec inferno session results "$session" > "$LANE_DIR/results.json"
    record "$LANE_DIR/results.json"
  fi
  pending
  return "$status"
}

case "${1:-}" in
  check) check ;;
  run) run ;;
  *)
    echo "usage: scripts/inferno/lane.sh check|run" >&2
    exit 2
    ;;
esac
