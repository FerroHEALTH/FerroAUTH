<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# VEX statements

Vulnerability Exploitability eXchange documents, in
[OpenVEX](https://openvex.dev) format, asserting the exploitability of
specific findings in what FerroAUTH publishes: the `ferrosmart` server
binary and the `ferrosmart` image built from it.

A VEX document carries the argument with it: each statement names the
vulnerability, the product, a `status`, a controlled-vocabulary
`justification`, and an `impact_statement` a reader can check.

## Rules

- **`not_affected` needs a justification from the OpenVEX vocabulary**, and
  the `impact_statement` says concretely why the code is unreachable in
  FerroSMART's usage. "Low risk" is not a justification.
- **A finding you can fix is fixed, not VEXed.** A statement exists for a
  finding whose fix belongs to someone else: an inherited base-image layer,
  or a dependency with no patched release.
- **Re-check on every base-image bump.** When the distroless base changes,
  statements about its packages may become obsolete, and a stale
  `not_affected` is worse than no VEX at all.
- **Every finding a FerroSMART release ships carries a statement.**
  `.github/workflows/release-ferrosmart.yml` scans the image on both
  platforms and the four server tarballs with no severity floor and unfixed
  findings included, and `scripts/checks/vex-coverage.sh` refuses the
  release while a finding has no statement here that judges it:
  `not_affected` with a `justification` or `impact_statement`, `affected`
  with an `action_statement`, or `fixed`. The products are named
  `pkg:oci/ferrosmart` and `pkg:cargo/ferrosmart`, and a statement matches a
  finding by its `vulnerability.name` or an `aliases` entry.

## Documents

There is no document yet. The image is built on
`gcr.io/distroless/static-debian13:nonroot` and carries one statically
linked musl binary, so the only Debian packages it holds are the base's data
packages, and `deny.toml` accepts no advisory, so no Rust finding needs a
judgement either. The first finding that cannot be fixed by a rebuild or a
bump adds its document here: a hand-written `ferrosmart-os.openvex.json` for
a base package, or, for an accepted Rust advisory, the generated
`rust-advisories.openvex.json` with its generator and checks
(`docs/release.md`, A security fix).
