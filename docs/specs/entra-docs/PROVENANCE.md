<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the Microsoft identity platform documents

Vendored verbatim by `scripts/vendor/entra-docs.sh`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/MicrosoftDocs/entra-docs>, rendered under
  <https://learn.microsoft.com/en-us/entra/identity-platform/>
- Pin: commit `219d8d57b01779e72e6d5449dc9341334c1fb906` (2026-11-05T13:36:57Z)
- Fetched: 2026-11-05, each file from raw.githubusercontent.com at the commit
  and checked against the git blob id the commit records
- Upstream licence: the repository's `README.md` states, verbatim:
  "Microsoft and any contributors grant you a license to the Microsoft documentation and other content in this repository under the [Creative Commons Attribution 4.0 International Public License](https://creativecommons.org/licenses/by/4.0/legalcode), see the [LICENSE](LICENSE) file, and grant you a license to any code in the repository under the [MIT License](https://opensource.org/licenses/MIT), see the [LICENSE-CODE](LICENSE-CODE) file." The `LICENSE` file it names for the documentation holds the
  MIT License text ("Copyright (c) Microsoft Corporation. Permission is
  hereby granted, free of charge, ... to deal in the Software without
  restriction, including without limitation the rights to use, copy, modify,
  merge, publish, distribute ..."), and `LICENSE-CODE` holds the MIT text
  too. Both statements are recorded here because they disagree; each allows
  a verbatim copy with the notice and attribution kept, which is what this
  directory is. The attribution is this file: the documents are
  Microsoft's. The README also states that the licences grant no right to
  Microsoft's names, logos or trademarks.
- Layout: the upstream paths, unchanged
- Files: 9
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `7440e03b474d255dfbf21b3788c7bc76dd28e592cbfae1403ddf4b6a4f62e89e`
- Read by: the `entra` issuer profile of #215, the person key of #216, the
  on-behalf-of grant of #217 and the `idp-entra` groups overage adapter of
  #221, vendored by #222

## What is taken

`docs/identity-platform/access-token-claims-reference.md` ("Access token claims
reference", with its "Groups overage claim" section),
`docs/identity-platform/optional-claims-reference.md` ("Optional claims reference", the
`idtyp` and `acct` claims) and `docs/identity-platform/v2-oauth2-on-behalf-of-flow.md`
("Microsoft identity platform and OAuth2.0 On-Behalf-Of flow"), with the
two include files and the one figure the flow page links. The other pages
and media of the repository are not taken.

| File | sha256 | git blob id |
|---|---|---|
| `LICENSE` | `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383` | `9e841e7a26e4eb057b24511e7b92d42b257a80e5` |
| `LICENSE-CODE` | `91f7258203fd43ba6d6f7f72b644eaedee9e3430f035c053beb6f34052f045e2` | `b17b032a43088ac7f3d2f3e34a2431c778a95e6f` |
| `README.md` | `32355274e726eb8981b4478aef7917313395ff7ca7be1904488c4adf8b818584` | `79e2f6397e79e79fb4a7593bfc5e50f34d94d06d` |
| `docs/identity-platform/access-token-claims-reference.md` | `e07447d46ab82957979f12b3caccaf9d07179c6556c7ffbde150d1f754f1e232` | `57501e33d517c90c2585fbae861a398a86239b6a` |
| `docs/identity-platform/includes/remind-not-to-relay-token-nonaud.md` | `892a33662da6c0b4d87ea486dee262072cf156812f9ce125fa52a2a13f454dd7` | `ffe0ae884ba91176669a3ebe6219b9bf806f8564` |
| `docs/identity-platform/includes/remind-not-to-validate-access-tokens.md` | `89490cd32926bba88c91caafc9d7154890c0d2eb8115e74f0d3a084c70a82e3c` | `cd036dd059795ede809e433d762fb9b53f812c68` |
| `docs/identity-platform/media/v2-oauth2-on-behalf-of-flow/protocols-oauth-on-behalf-of-flow.png` | `7fcfe78747e818500fba66fa9a49355e8092941cac76e0bcaca9ccb409043258` | `f0e4276f30b3a674385f66bc2d3b74f4d57ef37e` |
| `docs/identity-platform/optional-claims-reference.md` | `3b714c57087ee02fbc3ad49ddcd2399a144b2da2bca327b7cd9f7f0a0da797dc` | `19793d155dd2ecb567ebd2c18aba4fc90d7db27c` |
| `docs/identity-platform/v2-oauth2-on-behalf-of-flow.md` | `6c87ba39641729c561fb2e0785a1b460949397ddf8aafd0eaf95c55d8c9baddb` | `5e36d67c5b9631b81bdb8b29cf41e86e9aaccc92` |
