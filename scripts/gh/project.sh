#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# scripts/gh/project.sh: FerroSMART has no roadmap board.
#
# The FerroHEALTH products each keep a public GitHub Project (v2) board; this
# library repository keeps none, and this helper never creates one. The
# tracker is the issue list, milestones are the release spine, and the
# milestone page is the public view (.claude/rules/project-board.md). The
# helper stays so the shared skills and habits that call it get a clear
# answer instead of a GraphQL failure.
#
# Policy: no specification governs it: our own design.
#
# Usage:
#   scripts/gh/project.sh <any command> [args...]
#       Prints that this repository has no board and exits 0, touching
#       nothing on GitHub.
#   No argument or --help prints this usage and exits 2.

set -euo pipefail

usage() {
  sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

case "${1:-}" in
  '' | -h | --help) usage ;;
  *)
    echo "gh-project: FerroSMART has no roadmap board; nothing to do (.claude/rules/project-board.md)" >&2
    ;;
esac
