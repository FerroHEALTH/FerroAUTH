<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Memory index

- [Memory lives in the repo](memory-lives-in-repo.md): every learning is a
  tracked file here, never a per-user note
- [What FerroSMART is](ferrosmart.md): a library, never an authorization
  server; the resource server, the scopes, two machine-auth modes and the
  audit line every product shares; owner 2026-10-19
- [Crate name and licence](crate-name.md): the crate is `ferrohealth-smart`
  under BUSL-1.1, because hand-written code implementing a specification is
  BUSL in this family and only generator-emitted code is Apache; owner
  2026-10-19
- [Licence: BUSL 1.1](license-busl.md): the FerroHEALTH terms, Cadasto B.V.
  the Licensor, Apache 2.0 four years after each version
- [Signed commits and the merge queue](merge-queue-signed.md): `main` takes
  only signed commits through pull requests and the merge queue
- [PR licence box](pr-licence-box.md): tick the contribution-licence box in
  every pull request body; the owner's standing consent
- [Release tag](release-tag.md): the tag is signed on the merge commit and the
  crates-io environment waits for the owner's approval
- [All products in lockstep](lockstep.md): every release rolls out to every
  product at once, one pull request per product, coordinated from the
  FerroBRIDGE session
