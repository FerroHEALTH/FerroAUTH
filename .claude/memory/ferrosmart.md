---
name: ferrosmart
description: "FerroSMART holds the FerroHEALTH products' shared authentication and authorization crates, never an authorization server: ferrohealth-smart (the resource server, the SMART v2 scopes, HTTP Basic and the client credentials grant as the only machine-auth modes, the audit line) and ferrohealth-authz (the policy decision); owner 2026-10-19 and 2026-10-25"
metadata:
  type: project
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

FerroSMART (FerroHEALTH/FerroSMART) holds two shared crates every
FerroHEALTH product uses, the way FerroUI holds the shared UI crate
([[family-architecture]]):

- `ferrohealth-smart` on crates.io (owner, 2026-10-19): authentication,
  OAuth 2.0 and SMART App Launch 2.x, and the authenticated subject with
  its scopes and roles;
- `ferrohealth-authz`, the new crate for the policy decision (owner,
  2026-10-25): ABAC, Cedar and a remote PDP. The policy decision belongs
  there, never in `ferrohealth-smart` and never as a product's local copy.

The points below are about `ferrohealth-smart`.

- **Not an authorization server.** It never issues a token and never holds
  a key that signs one; each deployment points it at its own
  standards-compliant authorization server (Keycloak, Entra ID, Cadasto's
  smart-auth). The `private_key_jwt` key is a client credential that signs
  only the product's own client assertion (RFC 7523 §2.2), which the owner
  confirmed keeps "never holds a token-signing key" true.
- **What it is:** the resource server (discovery, the key set with
  rotation, RFC 9068 validation, one generic `401`), the SMART v2 scopes
  with the patient compartment and a `403` naming no scope, machine
  authentication in exactly two modes (HTTP Basic against Argon2id hashes,
  and the client credentials grant with a cache and one renewal on a `401`;
  no static bearer token, no API key), and one audit line per request.
- **The seams:** a tower layer and an axum extractor behind the `axum`
  feature; the core stays framework-neutral. FerroFED's introspection and
  edge mode stay product-specific behind the `Verifier` trait.
- **The authority** is the specifications vendored under `docs/specs/`,
  cited section by section in `docs/architecture.md` and in every
  `// NOTE:`.

**How to apply:** build every behaviour to `docs/architecture.md`; a change
that would issue a token, add a third machine-auth mode or name a product
in the library is refused and goes back to the owner. A policy decision
(roles and attributes evaluated against a rule set, Cedar, a PDP call)
goes to `ferrohealth-authz`, not to `ferrohealth-smart`.
