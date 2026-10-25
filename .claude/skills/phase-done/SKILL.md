---
name: phase-done
description: Closes a tracker issue by verifying the work is genuinely done (acceptance criteria, gates, docs, changelog), writing the close narrative into the PR description, ensuring the PR declares `Closes #N`, and posting the handoff comment. Use when the user says a work item is complete or asks to close it out.
allowed-tools: Read, Edit, Grep, Glob, Bash
argument-hint: "[issue number] (optional)"
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# /phase-done

The closing step of the issue workflow (`.claude/rules/issue-workflow.md`). Run
it only once the issue's work is actually finished; this skill verifies and
records, and it does not decide the work is done on your behalf.

## Steps

1. **Identify the issue being closed** (the user names it, or it is the issue
   this branch's PR declares `Closes #N` for). Read it with
   `gh issue view <n> --json title,body,comments --jq '.title, .body,
   (.comments[] | "--- comment ---", .body)'` (`--comments` prints nothing for
   an issue without comments, `issue-workflow.md` §The loop), and
   `scripts/gh/fields.sh show <n>` for its type, priority and effort. A Task
   carries exactly one work-kind label; a Bug or a Feature carries none. Set
   what is missing before closing (`issue-workflow.md` §Type, priority and
   labels).
2. **Verify every `## Acceptance criteria` checkbox is ticked.** If any remain
   `- [ ]`, stop and list them. Do not tick a criterion yourself to proceed; a
   tick must reflect real, verified state ("the workspace builds" means
   someone ran `cargo build --workspace` and it succeeded). Tick verified
   boxes in the issue body via
   `gh issue edit <n> --body-file`.
3. **Relationships check** (`scripts/gh/rel.sh tree <n>`;
   `.claude/rules/issue-relationships.md`): if the issue is a **parent** with
   **open sub-issues**, do NOT close it; finish or re-parent the children
   first. Closing this issue auto-unblocks anything it was `blocking`, which is
   expected; note any dependents that become workable so the handoff comment
   can point at them.
4. **Spec-adherence check:** for work that shipped spec-facing behaviour,
   confirm it was checked against the governing specification (the `spec-researcher` agent,
   `.claude/rules/spec-adherence.md`) and that the decisions carry citations.
   If that never happened, stop and say so; it is an unmet exit criterion in
   spirit.
5. **Research-issue check:** for a design-phase research issue, confirm the
   deliverable is on the issue thread as cited evidence and a recommendation,
   not as an undocumented conclusion. If the issue was supposed to change
   `docs/architecture.md`, confirm it did.
6. **Gate check:** confirm the gates that apply actually ran and passed: the
   shell and workflow set (`shellcheck --severity=style`, `actionlint`,
   `zizmor --min-severity=low .github/`), every guard under `scripts/checks/`
   that tier 1 of `ci.yml` runs, the `--self-test` of every `scripts/gh/`
   helper the change touched, and the full Rust set in
   `.claude/rules/ci-cd.md` for every crate the change touched. Report the
   results you saw, never a green you assumed.
7. **Changelog check:** a change with user-visible effect has an entry under
   `[Unreleased]` in `CHANGELOG.md`. Add it if it is missing.
8. **Write the close narrative into the PR description:** what shipped, the key
   decisions with their citations, the gate results, and what was deliberately
   left out (with follow-up issue numbers). The PR description plus the issue
   thread ARE the build record.
9. **Post the handoff comment on the issue** (`gh issue comment <n>`): where
   things stand at close, what was deliberately left out (with follow-up issue
   numbers), and what a follow-up session should do first.
10. **Ensure the PR body declares `Closes #<n>`** (`gh pr view`, `gh pr edit`)
    so the merge into `main` auto-closes the issue; never close the issue by
    hand when a PR carries the work. One `Closes` keyword per issue. Confirm
    auto-merge is armed (`gh pr view --json autoMergeRequest`); arm it if not,
    as its own command (`.claude/memory/pr-auto-merge.md`).
11. **Milestone check:** FerroAUTH has no roadmap board
    (`.claude/rules/project-board.md`). After the merge, confirm the issue is
    closed in its milestone (`gh issue view <n> --json state,milestone`).
12. **Remind the user to commit** the close on the current conventional-type
    branch.

## What this skill does not do

It does not run the build, the test suite, or the guards to "check" the
acceptance criteria for you; those must already have been run and have passed
before this skill is invoked. If in doubt, run the relevant command first.
