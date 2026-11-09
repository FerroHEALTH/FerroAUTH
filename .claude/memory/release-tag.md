---
name: release-tag
description: "A release is a signed vX.Y.Z tag on the merge commit on main; the session approves the crates-io gate itself (owner 2026-11-03)"
metadata:
  type: project
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

The release pull request bumps the workspace version, the changelog section
and the lock. After it merges, the tag `vX.Y.Z` is created signed
(`git tag -s`) on that merge commit and pushed; `release.yml` builds the
draft, attests the `.crate`, publishes the release, and its `crates` leg
pauses on the `crates-io` environment, which the session approves itself. `plan`
refuses the tag while the milestone titled as it is missing or holds an open
item, and the last job closes the milestone once every leg succeeded
([[release-closes-milestone]]).

**How to apply:** the session runs the whole cut: it arms the release PR with `gh pr merge <n> --auto`, signs and pushes the tag, and approves the `crates-io` deployment with `gh api -X POST repos/<repo>/actions/runs/<run>/pending_deployments` (owner, 2026-10-27 and 2026-11-03: "you can approve crates.io and also tag releases fully autonomously, without me asking anything"). Never move or delete a pushed tag (the `release-tags`
ruleset refuses it); a bad cut is fixed by a new patch version. A worker under a coordinating session reports the merge commit and leaves the tag to the coordinator.
