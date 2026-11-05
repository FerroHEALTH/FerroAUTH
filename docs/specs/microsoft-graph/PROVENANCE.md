<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the Microsoft Graph v1.0 reference pages

Vendored by `scripts/vendor/microsoft-graph.sh`, each artefact pinned by its
URL and the sha256 of its bytes. Never edit a file here: change the pins in
the script and the pin-set digest in docs/VERSIONS.md, and re-run the script.

- Pin-set digest (sha256 over the sorted `mode  file  url  sha256` lines of
  the pins): `e57d83b8670cc8285f92127af8f5717c49268af10083dadb1ce138fd7278b91c`
- Fetched: 2026-11-05, with the User-Agent `ferrohealth-smart-vendor (scripts/vendor)`
- Artefacts: 0 committed, 5 cache only, 0 needing
  manual retrieval
- Files in this directory: 0 besides this one, each verbatim as the
  publisher serves it
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Read by: the `idp-entra` groups overage adapter of #221

The Microsoft Graph v1.0 reference pages the `idp-entra` adapter reads a
person's group memberships through, from
<https://github.com/microsoftgraph/microsoft-graph-docs-contrib>, rendered
under <https://learn.microsoft.com/graph>. The repository's `LICENSE.md`
states the Creative Commons Attribution-NonCommercial-NoDerivs 3.0 United
States licence and its `LICENSE` holds the Creative Commons Attribution 4.0
International text. The statements disagree and the first allows no
commercial use, so every page is cache only and this repository carries none
of its content.

Examined and not taken: `user-list-memberof.md`, the paged listing of
directory objects, which the adapter does not call.

## Artefacts

### `directoryobject-getmemberobjects.md` (cache only, not redistributed)

- Source: <https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-docs-contrib/bb35043c742d4406d73ccae904c05fbfca7c7428/api-reference/v1.0/api/directoryobject-getmemberobjects.md>
- Version: microsoftgraph/microsoft-graph-docs-contrib commit bb35043c742d4406d73ccae904c05fbfca7c7428 (the default branch head on 2026-11-05)
- sha256: `622c6b4a6ca95b56ab2438a73a3f5b392bdcdc721afbfd70b2010e8b4c70046c`
- Licence: LICENSE.md: "This repository is licensed under the Creative Commons Attribution-NonCommercial-NoDerivs 3.0 United States license"; LICENSE: the Creative Commons Attribution 4.0 International text. The two disagree, and the first allows no commercial use
- Not redistributed: the script fetches it into `.vendor-cache/microsoft-graph/`, which git
  ignores; this repository carries none of its content.
- Note: POST /users/{id}/getMemberObjects and /servicePrincipals/{id}/getMemberObjects, the securityEnabledOnly body parameter, and 200 OK with a String collection in value

### `directoryobject-getmembergroups.md` (cache only, not redistributed)

- Source: <https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-docs-contrib/bb35043c742d4406d73ccae904c05fbfca7c7428/api-reference/v1.0/api/directoryobject-getmembergroups.md>
- Version: microsoftgraph/microsoft-graph-docs-contrib commit bb35043c742d4406d73ccae904c05fbfca7c7428 (the default branch head on 2026-11-05)
- sha256: `ec0107c0cb682da9562b5d034d904d5d7dd6b6d161139a86fedacdbc0913cb15`
- Licence: LICENSE.md: "This repository is licensed under the Creative Commons Attribution-NonCommercial-NoDerivs 3.0 United States license"; LICENSE: the Creative Commons Attribution 4.0 International text. The two disagree, and the first allows no commercial use
- Not redistributed: the script fetches it into `.vendor-cache/microsoft-graph/`, which git
  ignores; this repository carries none of its content.
- Note: The groups-only sibling, which returns up to 11,000 group IDs and answers 400 Directory_ResultSizeLimitExceeded above it

### `throttling.md` (cache only, not redistributed)

- Source: <https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-docs-contrib/bb35043c742d4406d73ccae904c05fbfca7c7428/concepts/throttling.md>
- Version: microsoftgraph/microsoft-graph-docs-contrib commit bb35043c742d4406d73ccae904c05fbfca7c7428 (the default branch head on 2026-11-05)
- sha256: `bcf59f10c6daad493751931665811baab232eb9be8e8aa201ae3f72233068e42`
- Licence: LICENSE.md: "This repository is licensed under the Creative Commons Attribution-NonCommercial-NoDerivs 3.0 United States license"; LICENSE: the Creative Commons Attribution 4.0 International text. The two disagree, and the first allows no commercial use
- Not redistributed: the script fetches it into `.vendor-cache/microsoft-graph/`, which git
  ignores; this repository carries none of its content.
- Note: A throttled request answers 429 Too Many Requests with a Retry-After header in seconds

### `LICENSE.md` (cache only, not redistributed)

- Source: <https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-docs-contrib/bb35043c742d4406d73ccae904c05fbfca7c7428/LICENSE.md>
- Version: microsoftgraph/microsoft-graph-docs-contrib commit bb35043c742d4406d73ccae904c05fbfca7c7428 (the default branch head on 2026-11-05)
- sha256: `306890513ee0cfa57c1aae38fc54dad8c27860d0d5d63f400ceacf1b604eb9cd`
- Licence: LICENSE.md: "This repository is licensed under the Creative Commons Attribution-NonCommercial-NoDerivs 3.0 United States license"; LICENSE: the Creative Commons Attribution 4.0 International text. The two disagree, and the first allows no commercial use
- Not redistributed: the script fetches it into `.vendor-cache/microsoft-graph/`, which git
  ignores; this repository carries none of its content.
- Note: The repository's licence statement

### `LICENSE` (cache only, not redistributed)

- Source: <https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-docs-contrib/bb35043c742d4406d73ccae904c05fbfca7c7428/LICENSE>
- Version: microsoftgraph/microsoft-graph-docs-contrib commit bb35043c742d4406d73ccae904c05fbfca7c7428 (the default branch head on 2026-11-05)
- sha256: `7183ef9749eb9b75e710a81a4c812a9405cc184f087500581a973e5929ac3f5e`
- Licence: LICENSE.md: "This repository is licensed under the Creative Commons Attribution-NonCommercial-NoDerivs 3.0 United States license"; LICENSE: the Creative Commons Attribution 4.0 International text. The two disagree, and the first allows no commercial use
- Not redistributed: the script fetches it into `.vendor-cache/microsoft-graph/`, which git
  ignores; this repository carries none of its content.
- Note: The Creative Commons Attribution 4.0 International text
