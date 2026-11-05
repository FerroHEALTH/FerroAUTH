<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the Okta OpenID Connect and OAuth 2.0 API reference

Vendored by `scripts/vendor/okta.sh`, each artefact pinned by its
URL and the sha256 of its bytes. Never edit a file here: change the pins in
the script and the pin-set digest in docs/VERSIONS.md, and re-run the script.

- Pin-set digest (sha256 over the sorted `mode  file  url  sha256` lines of
  the pins): `5eabc84f3fc280ea72504609b93738068dce65c672d8fafb2a2f758ef3e16706`
- Fetched: 2026-11-05, with the User-Agent `ferrohealth-smart-vendor (scripts/vendor)`
- Artefacts: 0 committed, 1 cache only, 0 needing
  manual retrieval
- Files in this directory: 0 besides this one, each verbatim as the
  publisher serves it
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Read by: the `okta` issuer profile of #215, vendored by #222

The "OpenID Connect & OAuth 2.0" API reference of Okta's developer
documentation, the overview page that lists the claims of an Okta access
token. Okta states that the page is "Copyright © 2026 Okta. All rights
reserved." and grants no licence to copy it, so it is cache only and this
repository carries none of its content.

Examined and not taken: the `okta/okta-developer-docs` repository, which
holds the guides of developer.okta.com and no source of this API reference
page, and which declares no licence.

## Artefacts

### `okta-oauth-overview.html` (cache only, not redistributed)

- Source: <https://developer.okta.com/docs/api/openapi/okta-oauth/guides/overview/>
- Version: no version stated; the page as served on 2026-11-05, re-pinned the same day after the first pin's bytes moved
- sha256: `c278d86c510d60d27ffe073a068d6ac8763358749a6017f449e9bc21f0d39ea9`
- Licence: Copyright © 2026 Okta. All rights reserved. (the page footer and <https://developer.okta.com/copyright/>, which adds "See Okta's Terms of Service for its Intellectual Property"); okta/okta-developer-docs carries no licence file and GitHub reports no licence for it
- Not redistributed: the script fetches it into `.vendor-cache/okta/`, which git
  ignores; this repository carries none of its content.
- Note: The reserved claims of the access token: uid ("A unique identifier for the user", absent when no user is bound to the token), cid ("Client ID of the client that requested the access token"), scp ("Array of scopes"), and a header whose only reserved claims are alg and kid
