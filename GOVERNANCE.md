<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Governance

How decisions get made in FerroAUTH, who makes them, and how that changes.

## Current structure: one maintainer

FerroAUTH has a single maintainer ([MAINTAINERS.md](MAINTAINERS.md)) who
holds final say on every technical decision: what gets built, merged and
released. There is no steering committee and no vote.

Cadasto B.V. is the Licensor and copyright holder (`LICENSE`) and handles the
business side, the commercial licence included: write to
[info@cadasto.com](mailto:info@cadasto.com) or use
<https://www.cadasto.com/contact/>. The maintainer handles the technical side.

## The products are the customers

FerroAUTH exists for the FerroHEALTH products. A change that alters what a
product accepts, refuses or records names that effect in its pull request
and changelog entry, and every product moves its exact version pin in
lockstep, in one pull request per product.

## Where decisions are recorded

| Kind of decision          | Where it lives                                                  |
|---------------------------|-----------------------------------------------------------------|
| What to build, and why    | the issue, with its acceptance criteria                         |
| How a check behaves       | the pull request, citing the specification section              |
| The design                | `docs/architecture.md`, with its decision register              |
| A release's contents      | its crate's `CHANGELOG.md` section and its milestone            |

## Becoming a maintainer

Sustained, reviewed contributions over several releases, a demonstrated grasp
of the specifications and the security bar, and the maintainer's invitation.
A new maintainer gains a row in [MAINTAINERS.md](MAINTAINERS.md) and their
handle in [`.github/CODEOWNERS`](.github/CODEOWNERS).

## Changing this document

By pull request, merged by the maintainer.
