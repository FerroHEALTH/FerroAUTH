---
name: ferrosmart
description: "FerroSMART is the shared SMART and OAuth 2.0 library of the FerroHEALTH products, never an authorization server: the resource server, the SMART v2 scopes, HTTP Basic and the client credentials grant as the only machine-auth modes, and the audit line; owner 2026-10-19"
metadata:
  type: project
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

FerroSMART (`ferrohealth-smart` on crates.io, FerroHEALTH/FerroSMART) is
the shared SMART App Launch 2.x and OAuth 2.0 crate every FerroHEALTH
product uses, the way FerroUI is the shared UI crate (owner, 2026-10-19).

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
in the library is refused and goes back to the owner.
