<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# No roadmap board

FerroSMART has no GitHub Project (v2) board, and none is created. The
FerroHEALTH products each keep a public roadmap board; this library
repository keeps its plan on the tracker alone (#24, 2026-10-20).

- **The tracker is the issue list** (`issue-workflow.md`): the native issue
  type and the organisation's `Priority` and `Effort` fields carry type,
  priority and effort; labels carry work kind and domain; native edges carry
  decomposition and sequencing (`issue-relationships.md`).
- **Milestones are the release spine and the public view.** The milestone
  page shows what a release holds and what is done; `release.yml` refuses a
  tag whose milestone holds an open item and closes it after the release.
- **No status to move.** There is no `Todo` / `In Progress` / `Done` column
  to keep true: an issue is open or closed, and a pull request that names it
  with `Closes #N` closes it on merge.

`scripts/gh/project.sh` stays as a stub: every command prints that this
repository has no board and exits 0 without calling GitHub, so a shared
habit or skill that calls it gets a clear answer. Never create a "FerroSMART
Roadmap" project, never add this repository's issues to another product's
board, and never extend the stub into a board client. Should the owner ever
want a board, that decision rewrites this file and the helper first.
