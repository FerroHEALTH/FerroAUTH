---
name: next-task
description: Reads the tracker (GitHub Issues), picks the pinned or top open issue (or the issue the user names, skipping blocked ones), and restates it as a concrete in-session work plan naming the sources and files involved. Use when the user asks "what's next" or "what should I work on".
allowed-tools: Read, Grep, Glob, Bash
argument-hint: "[issue number] (optional)"
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# /next-task

Turns an open tracker issue into an actionable plan, the planning step of the
issue workflow (`.claude/rules/issue-workflow.md`). It does not do the work;
that is a separate step the caller takes after seeing the plan.

## Steps

1. **Read the tracker**: `gh issue list --state open` (the SessionStart dump
   annotates each issue with `{k/n}` sub-issue progress, `child-of #parent`,
   and open `BLOCKED-by`/`blocks` edges, and prints `<Type/Priority>` after
   each title). Take the pinned issue (current focus) or the issue the user
   named; otherwise take the open, unblocked issue with the highest `Priority`
   field (`Urgent`, then `High`, `Medium`, `Low`), the oldest first within a
   priority. **Respect relationships**
   (`.claude/rules/issue-relationships.md`): do NOT pick an issue shown
   `BLOCKED-by` an open issue (surface its blocker as the real next task
   instead); for a parent issue, point at its next open child rather than the
   parent itself. An issue shown `<?/?>` has no type or priority yet (a
   scheduled lane filed it): set the type, the priority, the effort and the
   milestone with `scripts/gh/fields.sh` before planning it. Then
   `gh issue view <n> --json title,body,comments --jq '.title, .body,
   (.comments[] | "--- comment ---", .body)'` for the full contract (the
   opening summary plus `## Acceptance criteria`) and the running discussion
   (`--comments` prints nothing for an issue without comments,
   `issue-workflow.md` §The loop), and `scripts/gh/rel.sh tree <n>` for its
   parent, children, and blockers.
2. **Turn the task into a plan**, stating:
   - **What** the task requires, in one or two sentences.
   - **Which sources or files** are involved: the specification sections that
     govern the work, and the files, found by searching rather than guessing
     paths.
   - **Which mechanism** applies. A **research** issue produces cited evidence
     and a recommendation on the issue thread, and records a settled decision
     in the issue thread. An **implementation** issue is idiomatic Rust of our
     own design, built as compiling,
     tested increments.
   - **Which specifications govern it:** for any spec-facing task, name the
     authoritative source the work must be read against (SMART App Launch,
     the OAuth 2.0 and JOSE RFCs, or OpenID Connect Discovery, as vendored under
     `docs/specs/`), per `.claude/rules/spec-adherence.md` and
     the `spec-researcher` agent. Doing the work starts by reading those.
   - **What "done" looks like** for this task specifically: the issue's
     `## Acceptance criteria` checklist, plus what proves it.
3. **There is no board move.** FerroSMART has no roadmap board
   (`.claude/rules/project-board.md`), so starting or parking the issue
   changes nothing on GitHub.
4. **Do not edit the issue or commit:** recording progress happens after the
   work is actually done, not as part of planning it.
