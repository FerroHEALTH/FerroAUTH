---
name: lockstep
description: "Every FerroSMART release rolls out to every product at once (FerroBRIDGE, FerroEHR, FerroFED, FerroPIX, FerroTERM), one pull request per product, coordinated from the FerroBRIDGE session, as FerroUI's releases do"
metadata:
  type: project
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

Every FerroHEALTH product (FerroBRIDGE, FerroEHR, FerroFED, FerroPIX,
FerroTERM; [[family-architecture]]) depends on FerroSMART pinned exactly
(`=X.Y.Z`) from crates.io, never a submodule or a path dependency, the way
the products depend on FerroUI (owner, 2026-10-19).

- **All products move in lockstep.** Every FerroSMART release is rolled out
  to every product at once: a migration or pin-bump pull request in each
  repository, merged together, so no product runs an older FerroSMART than
  the others. The rollout is coordinated from the FerroBRIDGE session.
- **The first migration order** was `docs/architecture.md` §5.2:
  FerroBRIDGE, FerroTERM, FerroEHR, FerroFED. Every product stays green on
  its own gates and keeps every existing test.
- **Shared, never single use.** A behaviour a product needs and FerroSMART
  lacks is filed on FerroSMART and built there, in `ferrohealth-smart` or
  `ferrohealth-authz`, never as a local copy.

**How to apply:** a product's migration changes only the pin, the seams it
plugs in and the renames the changelog names; anything else found en route
is filed on the product's tracker.
