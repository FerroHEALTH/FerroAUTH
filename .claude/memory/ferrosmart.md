---
name: ferrosmart
description: "FerroSMART is the family's own SMART App Launch 2.x authorization server, in the FerroAUTH repository permanently, BUSL-1.1, shipped as its own OCI image; the one component that issues tokens and holds signing keys, any OIDC IdP upstream for login only; owner 2026-11-16"
metadata:
  type: project
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

The owner decided on 2026-11-16:

1. FerroHEALTH builds its own SMART App Launch 2.x authorization server,
   FerroSMART, because no IdP the family supports issues real SMART tokens.
   ZITADEL drops the SMART scopes and `launch`, puts no `scope` in its
   tokens and refuses spec-form asymmetric clients (FerroHEALTH/FerroEHR#5827,
   comment 6914641288); Keycloak as configured has fixed per-client scopes
   and no launch context. SMART must work for any IdP.
2. FerroSMART lives in the FerroAUTH repository permanently (no new
   repository, so fewer scattered products) and ships as its own OCI image
   and the family's release artefacts beside the library crates.
3. This lifts the rule "FerroAUTH is not an authorization server". The
   library crates stay resource-server, policy and session crates and never
   issue a token. FerroSMART is the one component that issues tokens and
   holds signing keys, and it uses any OIDC IdP upstream for login only.
4. FerroSMART is required for FerroEHR v6.0.0; v6.0.0-rc1 waits for it,
   because v6.0.0 must be the full, proper setup (FerroHEALTH/FerroEHR#5844).
5. Keycloak, ZITADEL, Entra ID and Okta all sit upstream of FerroSMART, each
   with cited configuration and a test (compose for the first two, contract
   tests over the vendored discovery and token shapes for the SaaS two).
6. Licence BUSL-1.1, like the rest of the family. "FerroSMART" was this
   repository's name until 2026-10-25; the product name is reused.

**Why:** a hospital's IdP cannot be relied on for SMART scopes, launch
context or asymmetric clients, and every family product needs them.

**How to apply:** standards only on every interface (SMART App Launch 2.2,
OAuth 2.x, OIDC, RFC 9068, 7662, 7009, 7523, 8414, 7591, 7636, later PAR,
DPoP, token exchange and FAPI 2.0), no Ferro-specific claim anywhere, any
OIDC IdP upstream and any FHIR server downstream by configuration, policy
as content (configuration or database, never code), PostgreSQL state for
stateless replicas, its own BALP and EHDS audit, built on the FerroSYS
crates and reusing `ferrohealth-smart` and `ferrohealth-session`. The
design is `docs/architecture.md` §13. Work that would make a library crate
issue a token goes to FerroSMART instead.
