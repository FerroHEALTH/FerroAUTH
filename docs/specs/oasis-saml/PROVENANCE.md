<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the OASIS SAML V2.0 standard and its Errata 05

Vendored by `scripts/vendor/oasis-saml.sh`, each artefact pinned by its
URL and the sha256 of its bytes. Never edit a file here: change the pins in
the script and the pin-set digest in docs/VERSIONS.md, and re-run the script.

- Pin-set digest (sha256 over the sorted `mode  file  url  sha256` lines of
  the pins): `e0068404c33afe1c8e31c345696a326750548adfb8da2e3dd0142424d4f6f9ae`
- Fetched: 2026-11-19, with the User-Agent `ferrohealth-smart-vendor (scripts/vendor)`
- Artefacts: 5 committed, 0 cache only, 0 needing
  manual retrieval
- Files in this directory: 5 besides this one, each verbatim as the
  publisher serves it
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `c4695e7cea98d0f69eb5f2c569640e56e39d584bbae3715d70f1eca6995f0f46`
- Read by: FerroSMART's upstream SAML 2.0 login (`app/ferrosmart/src/saml/`,
  FerroHEALTH/FerroSMART#688)

The Core, Bindings, Profiles and Metadata documents of the SAML V2.0
OASIS Standard and the Errata 05 composite, committed verbatim under the
OASIS notice each carries. Attribution: OASIS Security Services Technical
Committee, *Security Assertion Markup Language (SAML) V2.0*.

## Artefacts

### `saml-core-2.0-os.pdf` (committed)

- Source: <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf>
- Version: SAML V2.0 OASIS Standard, 15 March 2005
- sha256: `dc0890f88bfe862c9b39672bed76e2dcb0bedb03491cc41c161aea472b0468ab`
- Licence: The OASIS notice each document carries: "This document and translations of it may be copied and furnished to others ... provided that the above copyright notice and this paragraph are included on all such copies"; the PDF is committed unmodified
- Note: Assertions and Protocols: the assertion, the Response, the AuthnRequest, artifact resolution, the XML Signature profile (5.4) and encryption (6).

### `saml-bindings-2.0-os.pdf` (committed)

- Source: <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf>
- Version: SAML V2.0 OASIS Standard, 15 March 2005
- sha256: `80dde7953739eeb306484888ea128dd214e2b4a5dd16fbcbb231ef7ae18fa3f1`
- Licence: The OASIS notice each document carries: "This document and translations of it may be copied and furnished to others ... provided that the above copyright notice and this paragraph are included on all such copies"; the PDF is committed unmodified
- Note: The SOAP (3.2), HTTP-Redirect (3.4), HTTP-POST (3.5) and HTTP-Artifact (3.6) bindings.

### `saml-profiles-2.0-os.pdf` (committed)

- Source: <https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf>
- Version: SAML V2.0 OASIS Standard, 15 March 2005
- sha256: `5df9b874551941c7f03cb9270e67ea44f426b44a8fa642b8cf261064cc6f7de2`
- Licence: The OASIS notice each document carries: "This document and translations of it may be copied and furnished to others ... provided that the above copyright notice and this paragraph are included on all such copies"; the PDF is committed unmodified
- Note: The Web Browser SSO profile (4.1).

### `saml-metadata-2.0-os.pdf` (committed)

- Source: <https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf>
- Version: SAML V2.0 OASIS Standard, 15 March 2005
- sha256: `48656c21cc0cf26873ebec6792299de4f71c46ce5df73c707653b4c0b12117ae`
- Licence: The OASIS notice each document carries: "This document and translations of it may be copied and furnished to others ... provided that the above copyright notice and this paragraph are included on all such copies"; the PDF is committed unmodified
- Note: The entity and role descriptors, key descriptors and endpoints, and signed metadata (3).

### `saml-v2.0-errata05-os.pdf` (committed)

- Source: <https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.pdf>
- Version: SAML Version 2.0 Errata 05, OASIS Standard, 1 May 2012
- sha256: `c9f6d7c4d6b147066a24715076ac8b62269429fae8e27d53a03cf0d73651ace3`
- Licence: The OASIS notice each document carries: "This document and translations of it may be copied and furnished to others ... provided that the above copyright notice and this paragraph are included on all such copies"; the PDF is committed unmodified
- Note: The approved errata; E26 (assertions in the SSO profile), E43 and E93 (encryption), E46, E59, E81, E83, E91 and E92 are cited.
