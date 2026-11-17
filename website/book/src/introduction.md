<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Introduction

FerroSMART is a SMART App Launch 2.2 authorization server. A health app
sends a person to FerroSMART to ask for access to a FHIR or openEHR server.
FerroSMART sends them on to the identity provider your organisation already
runs to log in, shows them what the app asks for, and gives the app an
access token the server checks. The person's password never reaches
FerroSMART.

This book is for two readers:

- **The operator**, who runs FerroSMART: the [quickstart](install/quickstart.md),
  the [image](install/image.md), the [identity provider](install/upstream.md)
  upstream, the [configuration](configure/configuration.md), the
  [keys](operate/keys.md), the [audit records](operate/audit.md) and
  [day-to-day operations](operate/operations.md).
- **The integrator**, who writes an app, an EHR or a resource server: the
  [flows](integrate/flows.md), the [EHR launch API](integrate/ehr-launch.md)
  and [a server behind FerroSMART](integrate/resource-server.md).

FerroSMART is being built toward its first release,
v{{version:ferrosmart}}. Every page describes what the code on `main` does,
and the [release notes](changelog.md) list each change. The design of record,
with the specification section behind every decision, is
[`docs/architecture.md`](https://github.com/FerroHEALTH/FerroSMART/blob/main/docs/architecture.md)
§13 in the repository.

FerroSMART is one of the
[FerroHEALTH](https://ferrohealth.eu/) products. The pages that hold for
every product (the manufacturer, the security policy, the Cyber Resilience
Act and the EHDS) are in the [family book](https://ferrohealth.eu/docs/).
