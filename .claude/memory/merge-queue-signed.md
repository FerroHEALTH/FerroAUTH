---
name: merge-queue-signed
description: "main takes only signed commits, through pull requests and the merge queue gated on conclusion; gh pr update-branch --rebase strips the signature"
metadata:
  type: feedback
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

The `main` ruleset requires signed commits, a pull request, and the merge
queue gated on the `conclusion` check, as FerroBRIDGE's does.

**Why:** a server-side rebase drops the author's signature and the ruleset
then refuses the branch; the queue tests pull requests on top of `main`, so a
branch never has to be brought up to date by hand.

**How to apply:** arm a pull request with `gh pr merge <n> --auto` (the queue
sets the method). Fix a conflicting branch with a local, signed rebase or
merge, never `gh pr update-branch --rebase`. Never `--admin` without the owner
asking.
