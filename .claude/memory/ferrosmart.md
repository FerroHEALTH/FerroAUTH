---
name: ferrosmart
description: "FerroSMART is a FerroHEALTH product and this repository's name again (owner 2026-11-17): the family's own SMART App Launch 2.x authorization server, the one component that issues tokens and holds signing keys (owner 2026-11-16), beside the shared crates ferrohealth-smart, ferrohealth-authz and ferrohealth-session, which never issue a token (owner 2026-10-19, 2026-10-25)"
metadata:
  type: project
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

The owner decided on 2026-11-17 that this repository is FerroSMART again:
a product, not only a library repository. The owner renamed it on GitHub
from FerroHEALTH/FerroAUTH to FerroHEALTH/FerroSMART the same day, and
GitHub redirects the old URLs. This replaces the rename of 2026-10-25,
which had made the repository FerroAUTH, a shared-library repository.

1. **The name.** FerroSMART in prose, in the repository name and in every
   link. The crate names stay `ferrohealth-smart`, `ferrohealth-authz` and
   `ferrohealth-session`; only the repository and product name change.
2. **The layout.** The server is in `app/ferrosmart`; the three libraries
   are in `crates/`.
3. **The brand.** FerroSMART is a product, so it has its own hue and mark:
   the shield with the keyhole, bronze `#78350F` on a light ground and the
   yellow `#FBBF24` on a dark one (`assets/brand/`). The family's pages
   list it as a product, in that yellow.
4. **Cedar and the remote PDP** stay features of `ferrohealth-authz`, with
   no change in behaviour. The owner rethinks them after FerroEHR v6.

The server, as the owner decided on 2026-11-16:

- FerroHEALTH builds its own SMART App Launch 2.x authorization server
  because no IdP the family supports issues real SMART tokens. ZITADEL
  drops the SMART scopes and `launch`, puts no `scope` in its tokens and
  refuses spec-form asymmetric clients (FerroHEALTH/FerroEHR#5827, comment
  6914641288); Keycloak as configured has fixed per-client scopes and no
  launch context. SMART must work for any IdP.
- It lives in this repository permanently and ships as its own OCI image
  and the family's release artefacts beside the library crates, under
  BUSL-1.1 like the rest of the family.
- It is the one component that issues tokens and holds signing keys, and
  it uses any OIDC IdP upstream for login only. Keycloak, ZITADEL, Entra ID
  and Okta all sit upstream of it, each with cited configuration and a test.
- It is required for FerroEHR v6.0.0; v6.0.0-rc1 waits for it
  (FerroHEALTH/FerroEHR#5844).

The libraries (owner 2026-10-19 and 2026-10-25):

- `ferrohealth-smart` is the resource server (discovery, the key set with
  rotation, RFC 9068 validation, one generic `401`), the SMART v2 scopes
  with the patient compartment and a `403` naming no scope, machine
  authentication in exactly two modes (HTTP Basic against Argon2id hashes,
  and the client credentials grant with a cache and one renewal on a
  `401`; no static bearer token, no API key), and one audit line per
  request. Its seams are a tower layer and an axum extractor behind the
  `axum` feature; the core stays framework-neutral.
- `ferrohealth-authz` is the policy decision; a policy decision never goes
  into `ferrohealth-smart` and never into a product's local copy.
- No library crate issues a token or holds a key that signs one. The
  `private_key_jwt` key is a client credential that signs only the
  product's own client assertion (RFC 7523 §2.2).

**Why:** a hospital's IdP cannot be relied on for SMART scopes, launch
context or asymmetric clients, and every family product needs them; the
server that fills the gap is a product, and the repository carries its name.

**How to apply:** standards only on every interface (SMART App Launch 2.2,
OAuth 2.x, OIDC, RFC 9068, 7662, 7009, 7523, 8414, 7591, 7636, later PAR,
DPoP, token exchange and FAPI 2.0), no Ferro-specific claim anywhere, any
OIDC IdP upstream and any FHIR server downstream by configuration, policy
as content, PostgreSQL state for stateless replicas, its own BALP and EHDS
audit, built on the FerroSYS crates and reusing `ferrohealth-smart` and
`ferrohealth-session`. The server's design is `docs/architecture.md` §13.
Work that would make a library crate issue a token goes to the server; a
third machine-auth mode or a product named in a library goes back to the
owner.
