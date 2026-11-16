<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the ZITADEL documentation and API definitions

Vendored verbatim by `scripts/vendor/zitadel-docs.sh`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/zitadel/zitadel>, the documentation under
  `apps/docs/content/`, the v2 API definitions under `proto/`, the setup steps and
  the official compose file
- Pin: tag `v4.20.3`, which resolves to commit `a8b256c94b6d8615f12c05c54289600a06ca1912` (2026-11-13T11:55:38Z)
- Fetched: 2026-11-16, each file from raw.githubusercontent.com at the commit
  and checked against the git blob id the commit records
- Upstream licence: the repository is AGPL-3.0-only (`LICENSE`, vendored).
  Its `LICENSING.md`, vendored beside it, licenses `apps/docs/` and
  `proto/` under the Apache License 2.0, so the pages and the definitions
  are Apache-2.0. `cmd/setup/steps.yaml` and
  `deploy/compose/docker-compose.yml` are AGPL-3.0-only, copied verbatim
  for citation and never built, linked or modified. The files are
  unmodified.
- Images run, never vendored: `ghcr.io/zitadel/zitadel` (AGPL-3.0-only)
  and `ghcr.io/zitadel/zitadel-login` (the Login v2 UI, MIT), pinned by
  digest in docs/VERSIONS.md and run unmodified by the example
- Layout: the upstream paths, unchanged
- Files: 27
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `0ae979b0dda589cf3c83dd701d4a7021102cbd0074b2cbe6bb232ad26c32de89`
- Read by: FerroSMART's ZITADEL example and the role claim reader of
  `ferrohealth_smart::roles` (#523)

## What is taken

- `apps/docs/content/apis/openidoauth/`: the claims ZITADEL puts in an ID Token,
  among them the project role claims, the reserved scopes, the endpoints
  and the grant types.
- `apps/docs/content/guides/integrate/retrieve-user-roles.mdx`: the shape of the role
  claim, an object whose member names are the roles.
- `apps/docs/content/guides/integrate/login-ui/`: the OIDC flow through the Login v2
  UI and the custom login flow a scripted login drives.
- `apps/docs/content/self-hosting/`: running ZITADEL under compose with PostgreSQL,
  the configuration, the first-instance steps, the custom domain, the TLS
  modes and the login client.
- `cmd/setup/steps.yaml` and `deploy/compose/docker-compose.yml`: the
  first-instance defaults and the official compose file.
- `proto/zitadel/*/v2/`: the organization, project, application, OIDC
  application settings, user, authorization, session and OIDC services the
  bootstrap calls.

| File | sha256 | git blob id |
|---|---|---|
| `LICENSE` | `4df3c306dddaaf4baffdff5ca820cc679ac8cd6dc263c6a74517783e42fa7a3b` | `bae94e189e62df1b8d5bd11435d954b25bee9d7b` |
| `LICENSING.md` | `97a02685ee62bfd02b2e696580189807a193b81fcc37909818f9d19cef45394e` | `67aff71b730dfef8559dc71b8d4cb1716c45c636` |
| `apps/docs/content/apis/openidoauth/claims.mdx` | `136f756c685021bff0a835cad7a0be151453176cc8f7ba4bcbaa8bcd94c1ccc2` | `4a982351c7702d67cb4f79837f45e3a14bcfc638` |
| `apps/docs/content/apis/openidoauth/endpoints.mdx` | `da481abbf7d11d7fc3409baad0393a985f3bf5732e4062173f57af9b177a8323` | `addbfef2a1b69cb9f39da30d543b77d8ccbc11eb` |
| `apps/docs/content/apis/openidoauth/grant-types.mdx` | `0455350d47cc9989f874f4b64b9b359712b61503f77441801398fc8fcacd8cb9` | `bd303173093a86a71a1f67dd437c79aa4a0bac52` |
| `apps/docs/content/apis/openidoauth/scopes.mdx` | `43d3649accd295538cf3169095c074de8398a47a8fb03421678ea8042fa707e2` | `5a4e0905588b3aa19900b207dbf412dce45acc45` |
| `apps/docs/content/guides/integrate/login-ui/login-app.mdx` | `b06f3b3cb3b8e624f0ee612106e6da5ace49c7aed6e791c0c2c9e12630a0eaf1` | `ecdc3fcce20922a20e7d31ce370156be912c3dfc` |
| `apps/docs/content/guides/integrate/login-ui/oidc-standard.mdx` | `6fb12712152b8d5f4bd7da5eec4d113e2e567f3cdd0e928d3f6b93fb7f45a8af` | `d1e869fd0cdba557e989cddaa942766c58686f71` |
| `apps/docs/content/guides/integrate/login-ui/username-password.mdx` | `c315e0dbd896ef5273c4b9ba339976eaaac8070fd9178c5c511b4efb427d811e` | `dcd82d5629c5b6a47ca2699d994f199974cb0db7` |
| `apps/docs/content/guides/integrate/retrieve-user-roles.mdx` | `ec7a5edc155bc14403700f791b5ea0482281ae6750f9265ec380bdbb3e5dd3a7` | `6c417798d28cbb45ab52b2674c10dcc60e3a3a1f` |
| `apps/docs/content/self-hosting/deploy/compose.mdx` | `0066faeb74227850a2a281e4bf055fc6679c425b90145eb34ef3ffd393b0a915` | `69b5e9922b55f2a8dfa45d5ac377d6b803af59bc` |
| `apps/docs/content/self-hosting/manage/configure/configure.mdx` | `522056fc0fb4046e1c908b2328d42f1b17b1d7d737287dc9da51033cda31e467` | `4a8ddefbe3cc51bcc75c4ea49d2c442008fcee48` |
| `apps/docs/content/self-hosting/manage/configure/example-zitadel-init-steps.yaml` | `308162892fd1754990022b73876c91691ee4516463abd91e89be89aa583ed1a4` | `cd07d0ddfb1629636dd77e5ecf938981669933f9` |
| `apps/docs/content/self-hosting/manage/custom-domain.mdx` | `87ad8f42551f482ebbeb870c4836d7d1dbabfb3e9105e2c0b19b8f96a3265731` | `16526a7da299bc4aa8f87889ae0cf310c827b912` |
| `apps/docs/content/self-hosting/manage/database/_postgres.mdx` | `90acc1647f0a2b90c965de3ffe21ef3322d5787479e5806a9474edb89d4cb8de` | `85a13a0f4d6333c35f65c304ac290ccf0fbbe55b` |
| `apps/docs/content/self-hosting/manage/login-client.mdx` | `4e3d691dd3a1948a25e6882fb93463663578be8c1be5079c8961c5f6c5208423` | `3adc1f4ee62208e3ead4bcdaf974131a267bfc89` |
| `apps/docs/content/self-hosting/manage/tls_modes.mdx` | `6f71c71d7c8c8e812478f0207442df5a24303cdd703fec6afc120f0bfda12034` | `e488c02449d361b59d2a24f7a1cc6deed6f89909` |
| `cmd/setup/steps.yaml` | `0fab79eb9a50251813f8404fc274194833d5768d92f3c82d91a7bb44b9744eb2` | `3622f81b88d9a8c1a7a8efbca10b5dd9d3b2c961` |
| `deploy/compose/docker-compose.yml` | `38221d76e2e86b01fa4b692b87ac2ecce53efe0a33836e69b9d34a120068e12c` | `c1d836c2b519614e73b67e0ec48c0b158f2060c9` |
| `proto/zitadel/application/v2/application_service.proto` | `db6e732147d3f95707fd548f05a1357dab60a5a7640807cf9a393fded85f5507` | `256136f9febd382f8ad308dfe3ceebe5a99b9ecf` |
| `proto/zitadel/application/v2/oidc.proto` | `a910481a440a7e08579fb5badb384c3a5fb45004319cc35fd944811054c7b3ee` | `db5b22316c7af175f47c0a4372e4efc7e31c73b0` |
| `proto/zitadel/authorization/v2/authorization_service.proto` | `80c7035eb83e44b09efc5325bc8c2644a53df89c2cad69e5f0017c159ecd125d` | `bf93ffbb6ea54a3d346fd6d530d23d2c19147ff0` |
| `proto/zitadel/oidc/v2/oidc_service.proto` | `a7c125b8238be9f490dbd62ac0ac3725c1437156433d8627b22d4bedbe888858` | `55b39105694afdb1d57181387b5fe8617998ff17` |
| `proto/zitadel/org/v2/org_service.proto` | `b48f7e7e7d193107868e532a72930b79e7cf4ddef8cf0efc4ed235af51d0d2df` | `c01d53b8e82c8bbb4539b3bacaf6c385a30aae73` |
| `proto/zitadel/project/v2/project_service.proto` | `a7aec6d568b063198371703f776bad6012960bdfbceba92c1100f33593df2ef7` | `8b4cdfd14c167bdb9997ddde92c6b19a4bb81606` |
| `proto/zitadel/session/v2/session_service.proto` | `6bffbdb2c61fef42e3a982ba34a7ec83da692f2474cadaae93fc9d6f5fac44ab` | `794ea6752f1987d2d49d7086d3d5d6256eab1800` |
| `proto/zitadel/user/v2/user_service.proto` | `ae9cb9c529f2e0ab603151fa1ca99c3d1e1b555ceaa1bfc0f9b77384732fec4f` | `10d901124087a14a4c697684184b2c44c7f483d2` |
