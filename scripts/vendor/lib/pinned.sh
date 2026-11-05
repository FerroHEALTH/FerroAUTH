# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# shellcheck shell=bash
# Shared helpers for the corpora pinned file by file, by URL and sha256.
#
# A vendor's web page has no git commit to pin, so each artefact is pinned by
# the URL it is fetched from and the sha256 of its bytes. A script calls
# `pinned_begin` once, then for each corpus declares its
# artefacts with `pin` and calls `pinned_corpus`, which:
#
# - checks the pins against the corpus row of docs/VERSIONS.md, whose Pin
#   cell carries the pin-set digest (sha256 over the sorted
#   `mode  file  url  sha256` lines), so changing any pin changes the matrix;
# - downloads every artefact into a scratch directory and fails, before it
#   touches the tree, when any sha256 differs from its pin;
# - writes each `commit` artefact verbatim under docs/specs/<corpus>/, each
#   `cache` artefact under the git-ignored .vendor-cache/<corpus>/, and
#   fetches nothing for a `manual` row (a source behind a login or a bot
#   challenge);
# - writes docs/specs/<corpus>/PROVENANCE.md, which names every artefact, its
#   URL, version, sha256 and licence, whatever its mode.
#
# A `cache` artefact is material whose licence does not allow redistribution,
# or whose licence is unclear: it is read locally and never committed.
# Re-running with unchanged pins and unchanged upstream bytes reproduces the
# tree byte for byte; only the fetch date in PROVENANCE.md moves.
#
# With PINNED_DIGESTS_ONLY=1 a script prints each corpus and its pin-set
# digest and fetches nothing, which is how a re-pin reads the digest it
# writes into docs/VERSIONS.md.
#
# With PINNED_ONLY set to a space-separated list of corpus directories, a
# script checks every corpus's pins against docs/VERSIONS.md and fetches and
# writes only the listed ones, so one corpus can be re-pinned while another
# of the same script cannot be fetched (a publisher answering with a bot
# check) and keeps its tree.
#
# Requires: curl, shasum, awk, and scripts/vendor/lib/corpus.sh sourced first.
#
# No specification governs this file; it is FerroAUTH's own design, taken
# from the FerroHEALTH/FerroFED script of the same name.

pinned_cache_root=".vendor-cache"
pinned_browser_ua="Mozilla/5.0"
pinned_table=""

# The scratch directory every download of this run lands in, removed when the
# script exits.
pinned_begin() {
  pinned_scratch="$(mktemp -d)"
  # shellcheck disable=SC2064 # the scratch path is fixed now, on purpose
  trap "rm -rf '$pinned_scratch'" EXIT
}

# pin MODE FILE VERSION URL SHA256 LICENCE [NOTE]
#
# Adds one artefact to the corpus being declared. MODE is commit, cache or
# manual; SHA256 is `-` for a manual row. LICENCE is the licence statement as
# the publisher makes it (quoted verbatim where it is quoted) or the legal
# ground on which the text is free.
pin() {
  local mode="$1" file="$2" version="$3" url="$4" sha="$5" licence="$6" note="${7:--}"
  case "$mode" in
    commit | cache)
      grep -qE '^[0-9a-f]{64}$' <<< "$sha" || die "$file: '$sha' is not a sha256"
      ;;
    manual) [ "$sha" = "-" ] || die "$file: a manual row pins no sha256" ;;
    *) die "$file has mode '$mode', not commit, cache or manual" ;;
  esac
  case "$file" in
    */* | .* | '') die "'$file' is not a plain file name" ;;
    *) ;;
  esac
  case "$version$url$licence$note" in
    *$'\t'* | *$'\n'*) die "$file: a pin field carries a tab or a line break" ;;
    *) ;;
  esac
  local line
  printf -v line '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$mode" "$file" "$version" "$url" "$sha" "$licence" "$note"
  pinned_table="$pinned_table$line"
}

# The pin-set digest of the table $1: sha256 over its sorted
# `mode  file  url  sha256` lines.
pinned_digest() {
  awk -F'\t' 'NF >= 5 { print $1 "  " $2 "  " $4 "  " $5 }' <<< "$1" |
    LC_ALL=C sort | shasum -a 256 | cut -d' ' -f1
}

# Escapes the pipes of a value for Markdown.
pinned_md() {
  local text="$1"
  printf '%s' "${text//|/\\|}"
}

# pinned_corpus DIR ITEM TITLE ABOUT [AGENT] [READ_BY]
#
# Vendors the artefacts declared with `pin` since the last call. DIR is the
# corpus directory under docs/specs/, ITEM the Item cell of its
# docs/VERSIONS.md row, TITLE the provenance heading, ABOUT the Markdown
# paragraphs that say what the corpus is and on what ground each part is or
# is not redistributed, AGENT `browser` for a publisher that refuses a
# non-browser User-Agent (empty otherwise), and READ_BY the issues and code
# that read the corpus.
pinned_corpus() {
  local dir="$1" item="$2" title="$3" about="$4" agent="${5:-}" read_by="${6:-}"
  [ -n "$read_by" ] || die "$dir: no reader is named"
  local pins="$pinned_table"
  local dest="docs/specs/$dir" cache="$pinned_cache_root/$dir"
  # shellcheck disable=SC2154 # corpus_ua is set by corpus.sh, sourced first
  local ua="$corpus_ua" cell want digest tmp
  local mode file version url sha licence note got bad=0
  pinned_table=""
  [ "$agent" = "browser" ] && ua="$pinned_browser_ua"
  [ -d "${pinned_scratch:-}" ] || die "pinned_begin was not called"
  [ -n "$pins" ] || die "$dir: no artefact is pinned"

  digest="$(pinned_digest "$pins")"
  # A re-pin reads the new digest for docs/VERSIONS.md here, with nothing
  # fetched and nothing written.
  if [ "${PINNED_DIGESTS_ONLY:-}" = "1" ]; then
    printf '%s %s\n' "$dir" "$digest"
    return 0
  fi

  cell="$(corpus_pin_cell "$item")"
  want="$(grep -oE '[0-9a-f]{64}' <<< "$cell" | head -n1)"
  # shellcheck disable=SC2154 # corpus_matrix is set by corpus.sh, sourced first
  [ -n "$want" ] || die "the '$item' row of $corpus_matrix names no pin-set digest"
  [ "$digest" = "$want" ] \
    || die "$dir: the pins have pin-set digest $digest, $corpus_matrix records $want"
  if [ -n "${PINNED_ONLY:-}" ] && ! grep -qxF "$dir" <<< "${PINNED_ONLY// /$'\n'}"; then
    say "$dir: not in PINNED_ONLY, left as it is"
    return 0
  fi

  tmp="$pinned_scratch/$dir"
  mkdir -p "$tmp"

  while IFS=$'\t' read -r mode file version url sha licence note; do
    case "$mode" in
      commit | cache) ;;
      *) continue ;;
    esac
    say "$dir: fetching $file"
    curl --proto '=https' --tlsv1.2 -fsSL --retry 2 -m 300 -A "$ua" -o "$tmp/$file" "$url" \
      || die "$dir: the download of $file from $url failed"
    got="$(corpus_sha256 "$tmp/$file")"
    if [ "$got" != "$sha" ]; then
      # shellcheck disable=SC2154 # corpus_script is set by corpus.sh, sourced first
      printf '%s: %s: %s has sha256 %s, the pin records %s\n' \
        "$corpus_script" "$dir" "$file" "$got" "$sha" >&2
      bad=1
    fi
  done <<< "$pins"
  [ "$bad" -eq 0 ] || die "$dir: an upstream hash moved; the tree is unchanged"

  rm -rf "$dest" "$cache"
  mkdir -p "$dest"
  while IFS=$'\t' read -r mode file version url sha licence note; do
    case "$mode" in
      commit) cp "$tmp/$file" "$dest/$file" ;;
      cache)
        mkdir -p "$cache"
        cp "$tmp/$file" "$cache/$file"
        ;;
      *) ;;
    esac
  done <<< "$pins"

  pinned_provenance "$dir" "$title" "$about" "$pins" "$digest" "$ua" "$read_by"
}

# Writes the PROVENANCE.md of one corpus.
pinned_provenance() {
  local dir="$1" title="$2" about="$3" pins="$4" digest="$5" ua="$6" read_by="$7"
  local dest="docs/specs/$dir" cache="$pinned_cache_root/$dir"
  local mode file version url sha licence note heading
  local n_commit=0 n_cache=0 n_manual=0 fetched files tree body=""

  while IFS=$'\t' read -r mode file version url sha licence note; do
    [ -n "$mode" ] || continue
    case "$mode" in
      commit)
        n_commit=$((n_commit + 1))
        heading="committed"
        ;;
      cache)
        n_cache=$((n_cache + 1))
        heading="cache only, not redistributed"
        ;;
      *)
        n_manual=$((n_manual + 1))
        heading="needs manual retrieval"
        ;;
    esac
    body="$body

### \`$file\` ($heading)

- Source: <$url>
- Version: $(pinned_md "$version")"
    if [ "$mode" = "manual" ]; then
      body="$body
- sha256: none, nothing is fetched"
    else
      body="$body
- sha256: \`$sha\`"
    fi
    body="$body
- Licence: $(pinned_md "$licence")"
    case "$mode" in
      cache)
        body="$body
- Not redistributed: the script fetches it into \`$cache/\`, which git
  ignores; this repository carries none of its content."
        ;;
      manual)
        body="$body
- Needs manual retrieval: the source answers an automated client with a
  login or a bot challenge, so the script fetches nothing and this
  repository carries none of its content."
        ;;
      *) ;;
    esac
    if [ "$note" != "-" ]; then
      body="$body
- Note: $(pinned_md "$note")"
    fi
  done <<< "$pins"

  fetched="$(corpus_fetched)"
  files="$(corpus_file_count "$dest")"
  tree="$(corpus_tree_digest "$dest")"

  cat > "$dest/PROVENANCE.md" << PROV
<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: $title

Vendored by \`scripts/vendor/$corpus_script.sh\`, each artefact pinned by its
URL and the sha256 of its bytes. Never edit a file here: change the pins in
the script and the pin-set digest in docs/VERSIONS.md, and re-run the script.

- Pin-set digest (sha256 over the sorted \`mode  file  url  sha256\` lines of
  the pins): \`$digest\`
- Fetched: $fetched, with the User-Agent \`$ua\`
- Artefacts: $n_commit committed, $n_cache cache only, $n_manual needing
  manual retrieval
- Files in this directory: $files besides this one, each verbatim as the
  publisher serves it
- Tree digest (sha256 over the sorted per-file \`sha256  path\` listing,
  \`PROVENANCE.md\` excluded): \`$tree\`
- Read by: $read_by

$about

## Artefacts$body
PROV

  say "$dir: $n_commit committed, $n_cache cache only, $n_manual manual"
}
