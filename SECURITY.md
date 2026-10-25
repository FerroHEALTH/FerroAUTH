<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Security Policy

This document says which versions receive security fixes, how to report a
vulnerability privately, and how a fixed vulnerability is published. The
vulnerability-handling policy every FerroHEALTH product shares is on one page
of the family book, written by the manufacturer, Cadasto B.V.:
<https://ferrohealth.eu/docs/security.html>.

## Supported versions

Only the newest release is supported. When a new release is published, every
earlier release stops receiving fixes: there are no maintenance branches, no
long-term-support line and no backports. If you are not on the newest
release, upgrade; upgrading is free. Under the Cyber Resilience Act, Cadasto
B.V. commits to keep publishing security fixes for at least five years after
each release (Regulation (EU) 2024/2847 Art 13(8)) and ships them only in the
newest release (Art 13(10)).

| Artifact | Supported version | Where fixes ship |
| --- | --- | --- |
| Every published FerroAUTH artifact | the newest published release | the newest release |

- **Where fixes ship:** a security fix ships in a new release. Where it is
  technically feasible, that release is a patch with the fix alone, so the
  update is provided separately from functionality updates (Annex I Part
  II(2)); when a functional change has to ship with it, the release's
  `### Security` section opens with "Shipped with functional changes
  because:" and the reason, and the release notes carry it
  ([`docs/release.md`](docs/release.md#security-entries)).
- **The end month:** the release notes of each release state the month its
  five years end (Art 13(19)), counted from the date of its changelog
  heading.
- **Updates stay available:** a published release, its tag and each crate
  version on crates.io are never deleted.

A pre-release (a tag with a suffix, such as `v0.5.0-rc.1`) rehearses the
release lane and has no support period. `main` is unreleased and best
effort.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Report it
privately, through either route:

- [GitHub private vulnerability reporting](https://github.com/FerroHEALTH/FerroAUTH/security/advisories/new)
  ("Report a vulnerability" on the repository's Security tab), which needs a
  GitHub account; or
- email to [info@cadasto.com](mailto:info@cadasto.com), the single point of
  contact of Cadasto B.V., the manufacturer (CRA Art 13(17)), with "FerroAUTH
  vulnerability" in the subject. No account is needed. The address has no
  published encryption key, so send the details you are comfortable sending
  by email and say that more is available; a channel for the rest is agreed
  with you.

Both routes reach the same people and the same procedure.

## Response times

FerroAUTH is solo-maintained, so these are best effort rather than a
contractual service-level agreement. They are the times every product of the
Ferro family states: an acknowledgement within about 5 business days, and
an initial assessment (is it valid, how severe) within about 10 business days
of the report. A confirmed vulnerability is fixed in a new patch version,
published within the target for its severity, counted from the confirmed
assessment:

| Severity | Fixed release published within |
|---|---|
| Critical | 7 days |
| High | 30 days |
| Medium | 90 days |
| Low | the next release |

If the acknowledgement does not come in time, public disclosure to protect
other users is your call.

## Security advisories

A reported vulnerability gets a private draft of a GitHub security advisory
on this repository the day it is confirmed, and the draft is the record
until the fix ships. Every fixed vulnerability is published as that
advisory, in the same hour as the release that fixes it: one in FerroAUTH's
own code, and one for a dependency fix that changes what a published crate
builds into. The `### Security` entry for the fix in
[`CHANGELOG.md`](CHANGELOG.md) carries the advisory's `GHSA-` identifier,
and the release notes repeat it (CRA Annex I Part II(4), (8)). CI and the
release check both rules (`scripts/checks/changelog-security.sh`). The
advisories are machine-readable through the GitHub REST API
(`GET /repos/FerroHEALTH/FerroAUTH/security-advisories`).

## Vulnerability exploitability (VEX)

`deny.toml` accepts no advisory today, so FerroAUTH publishes no VEX
document yet. The document arrives with the first accepted advisory: an
OpenVEX statement under `security/vex/`, generated from `deny.toml` and the
reasoning beside it, which a scanner reads with `trivy --vex`, as FerroUI
and FerroPIX publish theirs. A dependency finding such a statement shows
does not affect FerroAUTH gets no advisory; its changelog entry names the
statement instead.
