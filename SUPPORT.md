<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Getting help

## I have a question

Start at the [README](README.md), the crate documentation on docs.rs
(<https://docs.rs/ferrohealth-smart>) and the design of record,
[`docs/architecture.md`](docs/architecture.md), which records every check
with its specification citation and the configuration model. If those do
not answer it, open an issue through the
[issue chooser](https://github.com/FerroHEALTH/FerroSMART/issues/new/choose).

There is no commercial support offering and no service-level agreement. A
commercial licence or any other business question goes to Cadasto B.V., the
Licensor: [info@cadasto.com](mailto:info@cadasto.com) or
<https://www.cadasto.com/contact/>.

## I found a defect

[Open an issue](https://github.com/FerroHEALTH/FerroSMART/issues/new/choose)
when a token is admitted that the specification refuses, a refusal names a
claim or a scope, a challenge or a status differs from the one the design
fixes, or a credential reaches a log line. The status, the
`WWW-Authenticate` challenge and the audit line help; never paste a real
token, key, secret or password.

## I found a vulnerability

Do not open an issue. Follow [SECURITY.md](SECURITY.md).
