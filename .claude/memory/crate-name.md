---
name: crate-name
description: "The crate is ferrohealth-smart (Rust path ferrohealth_smart), under BUSL-1.1 because it is hand-written code implementing a specification; owner 2026-10-19"
metadata:
  type: project
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

The crate is `ferrohealth-smart` (Rust path `ferrohealth_smart`). The
repository is `FerroHEALTH/FerroSMART`, and FerroSMART is the name in prose.

**Why:** the owner's decision of 2026-10-19, after considering a
standard-neutral name; the name is final. The owner reserved
`ferrohealth-smart` at `0.0.0` on crates.io the same day, so Trusted
Publishing takes over from `0.1.0`.

**The licence is BUSL-1.1**, not the Apache-2.0 of the family's generated
crates: under the family rule, hand-written code that implements a
specification is BUSL, and only generator-emitted code (`fhir-types`,
`hl7v2-types` in FerroBRIDGE) is Apache, because it is emitted from the
specifications' own inputs and three servers depend on it. `ferrohealth-smart`
emits nothing and is consumed by the family's own products (owner,
2026-10-19; `docs/architecture.md` §9).

**How to apply:** never rename the crate or the package, and never run
`cargo publish` under another name. Products depend on
`ferrohealth-smart = "=X.Y.Z"`.
