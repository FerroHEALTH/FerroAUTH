<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the Okta OpenID Connect and OAuth 2.0 API reference

Vendored by `scripts/vendor/okta.sh`, each artefact pinned by its
URL and the sha256 of its bytes. Never edit a file here: change the pins in
the script and the pin-set digest in docs/VERSIONS.md, and re-run the script.

- Pin-set digest (sha256 over the sorted `mode  file  url  sha256` lines of
  the pins): `c4c7b0a45106479bcdaea3c284f05455cbe9a812bdd05b537126f5d9c5ae42b7`
- Fetched: 2026-11-16, with the User-Agent `ferrohealth-smart-vendor (scripts/vendor)`
- Artefacts: 0 committed, 7 cache only, 0 needing
  manual retrieval
- Files in this directory: 0 besides this one, each verbatim as the
  publisher serves it
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Read by: the `okta` issuer profile of #215, vendored by #222; FerroSMART's Okta login (#525, docs/architecture.md §13.18)

The "OpenID Connect & OAuth 2.0" API reference of Okta's developer
documentation (the overview page that lists the claims of an Okta access
and ID token, client authentication, and the custom authorization server's
metadata), and the developer guides FerroSMART's Okta login cites. Okta
states that each page is "Copyright © 2026 Okta. All rights reserved."
and grants no licence to copy it, so all are cache only and this repository
carries none of their content: the documentation cites them by section.

Examined and not taken: the `okta/okta-developer-docs` repository, the
source of the guides, which holds no source of the API reference pages and
declares no licence; the guides are pinned as developer.okta.com renders
them.

## Artefacts

### `okta-oauth-overview.html` (cache only, not redistributed)

- Source: <https://developer.okta.com/docs/api/openapi/okta-oauth/guides/overview>
- Version: no version stated; the page as served on 2026-11-16, last updated October 6, 2026, re-pinned after the bytes of the 2026-11-05 pin moved
- sha256: `572ba6a714905712e698ccabf09fc25edfda704a0c66996fe793ef3385d29ff8`
- Licence: Copyright © 2026 Okta. All rights reserved. (the page footer and <https://developer.okta.com/copyright/>, which adds "See Okta's Terms of Service for its Intellectual Property"); okta/okta-developer-docs carries no licence file and GitHub reports no licence for it
- Not redistributed: the script fetches it into `.vendor-cache/okta/`, which git
  ignores; this repository carries none of its content.
- Note: The reserved claims of the access token: uid ("A unique identifier for the user", absent when no user is bound to the token), cid ("Client ID of the client that requested the access token"), scp ("Array of scopes"), and a header whose only reserved claims are alg and kid; the ID token's base and scope-dependent claims (sub, iss, aud, groups with its limit of 100), alg always RS256

### `okta-oauth-client-auth.html` (cache only, not redistributed)

- Source: <https://developer.okta.com/docs/api/openapi/okta-oauth/guides/client-auth>
- Version: no version stated; the page as served on 2026-11-16, last updated October 16, 2026
- sha256: `dd3af747e72aab0d0356b72e73e5b215d66aa2f45224357329d2e3e57caefcfc`
- Licence: Copyright © 2026 Okta. All rights reserved. (the page footer and <https://developer.okta.com/copyright/>, which adds "See Okta's Terms of Service for its Intellectual Property"); okta/okta-developer-docs carries no licence file and GitHub reports no licence for it
- Not redistributed: the script fetches it into `.vendor-cache/okta/`, which git
  ignores; this repository carries none of its content.
- Note: Client authentication methods: client_secret_basic is the default, the secret in the Authorization header as Basic

### `okta-oauth-customas.html` (cache only, not redistributed)

- Source: <https://developer.okta.com/docs/api/openapi/okta-oauth/oauth/customas>
- Version: no version stated; the page as served on 2026-11-16
- sha256: `d7c3f759434ccae74dc223749ef9c61f10bd64a5012d533527cf9442220ab97a`
- Licence: Copyright © 2026 Okta. All rights reserved. (the page footer and <https://developer.okta.com/copyright/>, which adds "See Okta's Terms of Service for its Intellectual Property"); okta/okta-developer-docs carries no licence file and GitHub reports no licence for it
- Not redistributed: the script fetches it into `.vendor-cache/okta/`, which git
  ignores; this repository carries none of its content.
- Note: Custom Authorization Servers: the RFC 8414 metadata at /.well-known/oauth-authorization-server/oauth2/{authorizationServerId} and the OpenID Connect metadata, with their members

### `okta-auth-servers.html` (cache only, not redistributed)

- Source: <https://developer.okta.com/docs/concepts/auth-servers/>
- Version: no version stated; the page as served on 2026-11-16
- sha256: `d185ad90b624f050d49e067f887058052ccdb7b2773d5c2c66c33356e9819773`
- Licence: Copyright © 2026 Okta. All rights reserved. (the page footer and <https://developer.okta.com/copyright/>, which adds "See Okta's Terms of Service for its Intellectual Property"); okta/okta-developer-docs carries no licence file and GitHub reports no licence for it
- Not redistributed: the script fetches it into `.vendor-cache/okta/`, which git
  ignores; this repository carries none of its content.
- Note: Authorization servers: the org and custom authorization servers, their issuers and discovery endpoints, the default custom authorization server

### `okta-customize-tokens.html` (cache only, not redistributed)

- Source: <https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/main/>
- Version: no version stated; the page as served on 2026-11-16
- sha256: `1a75024a98ba57132c2bd7439301eef72f64eb7672ecc618326993b5e970e60b`
- Licence: Copyright © 2026 Okta. All rights reserved. (the page footer and <https://developer.okta.com/copyright/>, which adds "See Okta's Terms of Service for its Intellectual Property"); okta/okta-developer-docs carries no licence file and GitHub reports no licence for it
- Not redistributed: the script fetches it into `.vendor-cache/okta/`, which git
  ignores; this repository carries none of its content.
- Note: Customize tokens returned from Okta: Add a custom claim to a token (custom authorization server only, Include in token type ID Token, Always, an Expression value)

### `okta-groups-claim.html` (cache only, not redistributed)

- Source: <https://developer.okta.com/docs/guides/customize-tokens-groups-claim/main/>
- Version: no version stated; the page as served on 2026-11-16
- sha256: `ad19f6f3f6d6f7cee0ac3c5835af9445b310ab0a91017c35a498843e41532605`
- Licence: Copyright © 2026 Okta. All rights reserved. (the page footer and <https://developer.okta.com/copyright/>, which adds "See Okta's Terms of Service for its Intellectual Property"); okta/okta-developer-docs carries no licence file and GitHub reports no licence for it
- Not redistributed: the script fetches it into `.vendor-cache/okta/`, which git
  ignores; this repository carries none of its content.
- Note: Customize tokens with a groups claim: Add a groups claim for a custom authorization server, a Groups filter matching a regex

### `okta-authcode.html` (cache only, not redistributed)

- Source: <https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/>
- Version: no version stated; the page as served on 2026-11-16
- sha256: `911e1d7b966315260b0b4ddfff044ae4948285812a8823b04c94decbaedcdda9`
- Licence: Copyright © 2026 Okta. All rights reserved. (the page footer and <https://developer.okta.com/copyright/>, which adds "See Okta's Terms of Service for its Intellectual Property"); okta/okta-developer-docs carries no licence file and GitHub reports no licence for it
- Not redistributed: the script fetches it into `.vendor-cache/okta/`, which git
  ignores; this repository carries none of its content.
- Note: Implement the Authorization Code grant: a Web Application integration, its Sign-in redirect URIs and the Basic authentication of the token request
