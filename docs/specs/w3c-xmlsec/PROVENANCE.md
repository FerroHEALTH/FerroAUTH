<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the W3C XML Signature, XML Encryption and canonicalization Recommendations

Vendored by `scripts/vendor/w3c-xmlsec.sh`, each artefact pinned by its
URL and the sha256 of its bytes. Never edit a file here: change the pins in
the script and the pin-set digest in docs/VERSIONS.md, and re-run the script.

- Pin-set digest (sha256 over the sorted `mode  file  url  sha256` lines of
  the pins): `e84f3413c80317b5b4475e06a378cb7c0ee9dc2d982dd82c9aa58d35685f5b65`
- Fetched: 2026-11-19, with the User-Agent `ferrohealth-smart-vendor (scripts/vendor)`
- Artefacts: 4 committed, 0 cache only, 0 needing
  manual retrieval
- Files in this directory: 4 besides this one, each verbatim as the
  publisher serves it
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `d36e5996ce9b63262d6a4ccc33f9e15b962c828975dfc569bfb842b3d88c2c8b`
- Read by: the eHDSI assertion check and the shared `xml` module of
  `ferrohealth-smart`, and FerroSMART's upstream SAML 2.0 login
  (FerroHEALTH/FerroSMART#688)

XML Signature 1.1, XML Encryption 1.1, Exclusive XML Canonicalization
1.0 and Canonical XML 1.0, committed verbatim under the W3C Document
License. Attribution: World Wide Web Consortium.

## Artefacts

### `xmldsig-core1.html` (committed)

- Source: <https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/>
- Version: W3C Recommendation, 11 April 2013
- sha256: `4924a334deb880e7e18b54cd6db037aa6b4d0186e626a26d636c124f8a2e07a3`
- Licence: The W3C Document License (https://www.w3.org/copyright/document-license/), which each page links: copies of the document may be distributed unmodified with its copyright notice
- Note: XML Signature 1.1: the signature syntax, the reference processing and the algorithm requirements (6.1).

### `xmlenc-core1.html` (committed)

- Source: <https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/>
- Version: W3C Recommendation, 11 April 2013
- sha256: `40e83298cc2e53c565bebf8b8345c14edabea77d56a3a3698ca438730afec1ce`
- Licence: The W3C Document License (https://www.w3.org/copyright/document-license/), which each page links: copies of the document may be distributed unmodified with its copyright notice
- Note: XML Encryption 1.1: EncryptedData and EncryptedKey, AES-GCM, AES-CBC and its padding, RSA-OAEP (5).

### `xml-exc-c14n.html` (committed)

- Source: <https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/>
- Version: W3C Recommendation, 18 July 2002
- sha256: `10b1ec71542db546b311a3e600589339505b9099bc60affafa4204ece31807e3`
- Licence: The W3C Document License (https://www.w3.org/copyright/document-license/), which each page links: copies of the document may be distributed unmodified with its copyright notice
- Note: Exclusive XML Canonicalization 1.0, the one canonicalization accepted.

### `xml-c14n.html` (committed)

- Source: <https://www.w3.org/TR/2001/REC-xml-c14n-20010315>
- Version: W3C Recommendation, 15 March 2001
- sha256: `09c02ef3bc0f8364b00b16fb06092637c08e8f38cf223d47a5862eacc2956bc0`
- Licence: The W3C Document License (https://www.w3.org/copyright/document-license/), which each page links: copies of the document may be distributed unmodified with its copyright notice
- Note: Canonical XML 1.0, whose text and attribute rules (2.2, 2.3) the exclusive form inherits.
