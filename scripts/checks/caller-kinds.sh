#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The caller kinds the documentation lists against the code. `CallerKind`
# in crates/ferrohealth-smart/src/kind.rs is the one list: its `as_str` names
# what the audit line records, and its variants are what `Caller::kind`
# answers. The guard fails when the `kind` row of the audit line table in
# docs/architecture.md does not list exactly the `as_str` names, or the
# sentence of crates/ferrohealth-smart/README.md that opens with
# "`Caller::kind` answers" does not list exactly the variants (no
# specification governs this: our own design).
#
#   scripts/checks/caller-kinds.sh
#   scripts/checks/caller-kinds.sh --self-test
#
# Exit 0 when both agree, 1 naming each difference, 2 on a usage error.
set -euo pipefail

# shellcheck source=scripts/lib/guard-args.sh
. "$(dirname "$0")/../lib/guard-args.sh"
readonly GRAMMAR="[--self-test]"
guard_known_flags "$GRAMMAR" "--self-test" "$@"

# The arms of `CallerKind::as_str` in the kind.rs at $1, one
# "Variant<TAB>name" line each.
code_kinds() {
  awk '
    /^impl CallerKind \{/ { in_impl = 1; next }
    in_impl && /^\}/ { exit }
    in_impl && /fn as_str/ { in_fn = 1; next }
    in_fn && /^    \}/ { exit }
    in_fn && /Self::[A-Za-z]+.*=> "[a-z_]+"/ {
      v = $0; sub(/.*Self::/, "", v); sub(/[^A-Za-z].*/, "", v)
      n = $0; sub(/.*=> "/, "", n); sub(/".*/, "", n)
      print v "\t" n
    }
  ' "$1"
}

# The backticked words of $1, one per line, sorted, without `-`.
# shellcheck disable=SC2016 # the backticks are Markdown code spans, matched literally
ticked() {
  grep -oE '`[A-Za-z_]+`' <<< "$1" | tr -d '`' | LC_ALL=C sort -u || true
}

# The names the `kind` row of the architecture at $1 lists.
# shellcheck disable=SC2016 # the backticks are Markdown code spans, matched literally
architecture_kinds() {
  local row
  row="$(grep -E '^\| `kind` \| the caller kind' "$1" || true)"
  ticked "${row#*| the caller kind}"
}

# The variants the README at $1 lists after "`Caller::kind` answers", up to
# the end of that sentence's list.
# shellcheck disable=SC2016 # the backticks are Markdown code spans, matched literally
readme_kinds() {
  local text list
  text="$(tr '\n' ' ' < "$1" | tr -s ' ')"
  [[ "$text" == *'`Caller::kind` answers '* ]] || return 0
  list="${text#*\`Caller::kind\` answers }"
  list="${list%%, and *}"
  ticked "$list"
}

# compare WHAT FILE WANT GOT: prints each name missing from or extra in
# FILE; returns 1 when there is any.
compare() {
  local what="$1" file="$2" want="$3" got="$4" missing extra bad=0
  missing="$(LC_ALL=C comm -23 <(printf '%s\n' "$want") <(printf '%s\n' "$got") | grep -v '^$' || true)"
  extra="$(LC_ALL=C comm -13 <(printf '%s\n' "$want") <(printf '%s\n' "$got") | grep -v '^$' || true)"
  if [[ -z "$got" ]]; then
    echo "caller-kinds: $file lists no $what" >&2
    return 1
  fi
  if [[ -n "$missing" ]]; then
    echo "caller-kinds: $file does not list the $what $(paste -sd, - <<< "$missing")" >&2
    bad=1
  fi
  if [[ -n "$extra" ]]; then
    echo "caller-kinds: $file lists $(paste -sd, - <<< "$extra"), which CallerKind does not have" >&2
    bad=1
  fi
  return "$bad"
}

# check ROOT: the rule over the tree at ROOT.
check() {
  local root="$1" kinds names variants status=0
  kinds="$(code_kinds "$root/crates/ferrohealth-smart/src/kind.rs")"
  if [[ -z "$kinds" ]]; then
    echo "caller-kinds: no CallerKind::as_str arm found in crates/ferrohealth-smart/src/kind.rs" >&2
    return 1
  fi
  names="$(cut -f2 <<< "$kinds" | LC_ALL=C sort -u)"
  variants="$(cut -f1 <<< "$kinds" | LC_ALL=C sort -u)"
  compare "caller kind" docs/architecture.md "$names" "$(architecture_kinds "$root/docs/architecture.md")" || status=1
  compare "CallerKind variant" crates/ferrohealth-smart/README.md "$variants" \
    "$(readme_kinds "$root/crates/ferrohealth-smart/README.md")" || status=1
  [[ "$status" -eq 0 ]] || return 1
  echo "caller-kinds: the architecture and the README list the $(wc -l <<< "$names" | tr -d ' ') caller kinds of CallerKind"
}

# shellcheck disable=SC2016 # the backticks are Markdown code spans, matched literally
self_test() {
  local work fails=0
  work="$(mktemp -d)"
  # shellcheck disable=SC2064 # expand now: $work is local and gone at EXIT time
  trap "rm -rf '$work'" EXIT
  mkdir -p "$work/crates/ferrohealth-smart/src" "$work/docs"
  cat > "$work/crates/ferrohealth-smart/src/kind.rs" << 'RS'
impl IssuerKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Persons => "persons",
        }
    }
}

impl CallerKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Patient => "patient",
            Self::Guest(_) => "guest",
            Self::ExternalPerson(_) => "external_person",
        }
    }
}
RS
  # expect NAME WANT_RC NEEDLE ROW README: writes the architecture row and
  # the README sentence and checks the exit code and that NEEDLE is printed.
  expect() {
    local name="$1" want="$2" needle="$3" row="$4" readme="$5" out rc
    printf '| Field | Value |\n|---|---|\n%s\n' "$row" > "$work/docs/architecture.md"
    printf '# Readme\n\n- **`kind`**: who calls. `Caller::kind` answers\n  %s, and a token that matches no step is refused.\n' \
      "$readme" > "$work/crates/ferrohealth-smart/README.md"
    set +e
    out="$(check "$work" 2>&1)"
    rc=$?
    set -e
    if [[ "$rc" != "$want" || "$out" != *"$needle"* ]]; then
      echo "caller-kinds self-test: $name: exit $rc (want $want), output: $out" >&2
      fails=$((fails + 1))
    fi
  }
  local row='| `kind` | the caller kind (3.14): `patient`, `guest` or `external_person`, `-` for an open route |'
  local readme='`Patient`, `Guest` or `ExternalPerson`'
  expect "both agree" 0 "list the 3 caller kinds" "$row" "$readme"
  expect "a kind missing from the row" 1 "does not list the caller kind external_person" \
    '| `kind` | the caller kind (3.14): `patient` or `guest`, `-` for an open route |' "$readme"
  expect "a kind the code does not have" 1 "lists system, which CallerKind does not have" \
    '| `kind` | the caller kind (3.14): `patient`, `guest`, `external_person` or `system` |' "$readme"
  expect "a variant missing from the README" 1 "does not list the CallerKind variant ExternalPerson" \
    "$row" '`Patient` or `Guest`'
  expect "no row at all" 1 "lists no caller kind" '| `via` | `bearer` |' "$readme"
  if [[ "$fails" -gt 0 ]]; then
    echo "caller-kinds self-test FAILED ($fails case(s))" >&2
    exit 1
  fi
  echo "caller-kinds self-test OK"
}

if [[ "${1:-}" == "--self-test" ]]; then
  [[ "$#" -eq 1 ]] || guard_usage "$GRAMMAR"
  self_test
  exit 0
fi
[[ "$#" -eq 0 ]] || guard_usage "$GRAMMAR"
check "$(cd "$(dirname "$0")/../.." && pwd)"
