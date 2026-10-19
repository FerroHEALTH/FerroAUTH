<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# The public roadmap board (GitHub Project v2)

The tracker is GitHub Issues (`issue-workflow.md`); milestones are the
release spine; the native issue type and the organisation's `Priority` and
`Effort` issue fields carry type, priority and effort; labels carry work kind
and domain; native edges carry decomposition and sequencing
(`issue-relationships.md`). The **"FerroSMART Roadmap"
Project** (a GitHub Project v2 under the `FerroHEALTH` organization,
<https://github.com/orgs/FerroHEALTH/projects/3>) exists for one
reason: **outward transparency:** anyone can see what is planned, in progress,
and shipped, without reading the raw issue list. It is a **VIEW over the
tracker, never a second tracker.** This file is the policy (what the board may
and may not carry) and the canonical commands (the one sanctioned write path is
`scripts/gh/project.sh`).

## Owner-created

**The board does not exist until the owner creates it.** The repository owner
must create a GitHub Project (v2) titled **"FerroSMART Roadmap"** under the
`FerroHEALTH` organization, with the built-in single-select `Status` field carrying
exactly `Todo` / `In Progress` / `Done`, plus a Date field named `Target date`
for the roadmap layout, and grant the working clone the `project` token scope
(`gh auth refresh -s project`). Until then, every `scripts/gh/project.sh`
command fails loud with "no project titled 'FerroSMART Roadmap'". The board
configuration intent (fields, views, automations) is at the bottom of this file.

## The one-datum rule

**Status (`Todo` / `In Progress` / `Done`) is the ONLY board-managed datum.**
Everything else the board displays is read straight from the issue and already
has a canonical home:

| Fact | Canonical home | NEVER duplicated as |
|---|---|---|
| Priority | the organisation's `Priority` issue field (`scripts/gh/fields.sh`) | a board Priority field |
| Type | the native issue type (`Bug`/`Feature`/`Task`) | a board Type field |
| Effort | the organisation's `Effort` issue field (`scripts/gh/fields.sh`) | a board Effort/estimate field |
| Release | the `vX.Y.Z` milestone | a board Release/Iteration field |
| Decomposition | native sub-issue edges | a board hierarchy field |
| Sequencing | native blocked-by edges | a board Blocked column/field |

Do not add custom fields, iteration fields, estimate fields, or extra Status
options. A board-only fact has no backlink, is invisible to `gh issue`
consumers (the SessionStart dump, `/phase-status`, `/next-task`), and rots the
first time it disagrees with the field, label or milestone it shadows, the
same decay class `issue-relationships.md` §No duplication bans for issue
bodies. If the board ever needs to show a new fact, give the fact a canonical
home on the ISSUE (issue field, label, milestone, native edge) and let the
board filter/group on it.

**The ONE sanctioned derived field: `Target date`.** The roadmap layout places
items only by date/iteration fields (milestone due dates draw timeline
markers, never item bars), so `Target date` exists as a machine-derived mirror
of the item's milestone due date. It is written ONLY by
`scripts/gh/project.sh sync-dates` (re-run after changing a milestone due date
or re-milestoning issues), never by hand.

**No fourth Status, no manual "Blocked/Stalled" column.** Blocked-ness already
has an automatic canonical home: native `blocked-by` edges (GitHub renders the
red "Blocked" badge on those cards by itself, and clears it the moment the
blocker closes). A hand-moved status would double-book that and keep claiming
"stalled" after the blocker closes.

## Status semantics + who moves it

- **`Todo`:** every open issue starts here (the auto-add workflow sets it).
- **`In Progress`:** set at pickup, when work on the issue actually starts
  in a session: `scripts/gh/project.sh status <n> in-progress`. `/next-task`
  does this as its final step. This is the ONE manual move in the lifecycle:
  GitHub has no built-in "branch/PR opened → In Progress" workflow.
- **`Done`:** never set by hand. The issue closes via the PR's `Closes #N`
  and the built-in "item closed → Done" workflow moves it. A reopened issue
  goes back to `Todo` automatically.

An issue abandoned mid-flight (session ended, work parked) goes back to
`todo` explicitly; a stale `In Progress` column is a false public claim.

## The one sanctioned command surface: `scripts/gh/project.sh`

Projects v2 writes (`gh project item-edit`) take four opaque GraphQL node ids
(project, field, option, item), never the issue `#number`. The helper
resolves them all from the `#number` and fails loud. Requires the `project`
token scope (`gh auth refresh -s project`).

| Intent | Command |
|---|---|
| Start work on #n | `scripts/gh/project.sh status <n> in-progress` |
| Park #n (work stopped, not done) | `scripts/gh/project.sh status <n> todo` |
| Put #n on the board (auto-add missed it) | `scripts/gh/project.sh add <n>` |
| Read #n's board status | `scripts/gh/project.sh show <n>` |
| Print the whole board by column | `scripts/gh/project.sh board` |
| Print the project URL | `scripts/gh/project.sh url` |
| Post a status update | `scripts/gh/project.sh update <on-track\|at-risk\|off-track\|complete\|inactive> "<markdown>" [--start YYYY-MM-DD] [--target YYYY-MM-DD]` |
| Read recent status updates | `scripts/gh/project.sh updates` |
| Sync Target date from milestones | `scripts/gh/project.sh sync-dates` |

Never move `Done` by hand, never `gh project item-edit` raw, and never
`item-archive`/`item-delete`; closed items stay visible as the shipped record.
The one deletion the helper performs belongs to a transfer: GitHub moves a
project item along with an issue transferred to another repository, so the
board would otherwise show a foreign issue as ours. An issue leaves this
repository ONLY through `scripts/gh/project.sh transfer <n> <owner/repo>`,
which moves it and drops its card in one step; `project.sh transferred
<owner/repo>#<n>` repairs a transfer someone ran raw. Never run
`gh issue transfer` by hand.

## Status updates (the board's progress narrative)

GitHub project **status updates** (shown in the board header + side panel) are
the outward progress narrative. Post one via `scripts/gh/project.sh update …`:

- **At every release cut**: status `on-track` (or the honest alternative), a
  short markdown summary of what the release shipped and what the next
  milestone targets, `--target` = the next milestone's due date **only if that
  milestone actually has one**; never invent a date.
- **When direction genuinely shifts** (a milestone re-scoped, a program
  re-prioritized): post the change with the reason.
- Write for the public reader: no internal codenames, phase markers, or
  repo-internal file paths; numbers only when they come from committed
  artifacts. `at-risk`/`off-track` are used when true.

## Board configuration (the intent, for the owner creating it)

Fields: the built-in `Status` with exactly `Todo` / `In Progress` / `Done`,
plus a Date field `Target date` (kept true by `sync-dates`). Views:

1. **Board:** board layout, grouped by Status, sliced by Milestone; the
   "what is going on right now" surface.
2. **Roadmap:** roadmap layout, filter `is:open`; items placed by the derived
   `Target date` field; group by Milestone; milestone markers on.
3. **Current focus:** table layout, filter `is:open` with the `Priority`
   field at `Urgent` or `High`; columns
   Title/Status/Type/Priority/Labels/Milestone/Sub-issues progress.
4. **Needs attention:** table layout, filter `is:open` with the `Priority`
   field at `Urgent`.

Built-in workflows: Auto-add to project (`is:issue is:open` → Todo), Item
reopened → Todo, Item closed → Done, Pull request linked to issue → In Progress.
Keep **Auto-close issue OFF** (the board is a view and must never mutate the
tracker; closing happens only via the PR's `Closes #N`) and **Auto-archive
OFF** (closed items stay visible as the shipped record). Visibility: public.

## Interaction with the rest of the workflow

- **`/next-task`** moves the picked issue to `In Progress` once the plan is
  accepted and work starts.
- **`/phase-done`** verifies the closing issue lands in `Done` (the merge +
  workflow do it; the skill only checks).
- **`/phase-status`** may cite `scripts/gh/project.sh board` for the public
  view, but the issue list stays the working ground truth.

## Official documentation (durable citations)

- gh project commands: https://cli.github.com/manual/gh_project
- Projects v2 API: https://docs.github.com/en/issues/planning-and-tracking-with-projects/automating-your-project/using-the-api-to-manage-projects
- Built-in workflows: https://docs.github.com/en/issues/planning-and-tracking-with-projects/automating-your-project/using-the-built-in-automations
- Roadmap layout: https://docs.github.com/en/issues/planning-and-tracking-with-projects/customizing-views-in-your-project/customizing-the-roadmap-layout
