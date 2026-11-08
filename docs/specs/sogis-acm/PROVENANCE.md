<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the SOG-IS Agreed Cryptographic Mechanisms

Vendored by `scripts/vendor/sogis-acm.sh`, each artefact pinned by its
URL and the sha256 of its bytes. Never edit a file here: change the pins in
the script and the pin-set digest in docs/VERSIONS.md, and re-run the script.

- Pin-set digest (sha256 over the sorted `mode  file  url  sha256` lines of
  the pins): `195a4255de680cff0fa08587b79e42f27960a912c110d7fc053390b55dc6800a`
- Fetched: 2026-11-08, from the owner's local copies; nothing is downloaded
- Artefacts: 0 committed, 0 cache only, 0 needing
  manual retrieval, 1 read and not redistributed
- Files in this directory: 0 besides this one, each verbatim as the
  owner supplied it
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Read by: the eHDSI assertion check (#294: the RSA modulus floor of 3000 bits and
  the hash floor of SHA-256 its signer and signature are held to)

The SOG-IS Crypto Evaluation Scheme Agreed Cryptographic Mechanisms 1.3
(February 2023), published by the SOG-IS Crypto Working Group at
<https://www.sogis.eu/uk/supporting_doc_en.html>. eHDSI Cryptographic
Algorithms 9.0.0 §2 and the NCPeH Components Specifications 10.0.0 §5.1
(both in docs/specs/ehdsi-specifications/) set its "Legacy valid beyond
2025" level as the floor of the MyHealth@EU keys, hashes and cipher
suites.

Neither the document nor the SOG-IS page states a copyright, licence,
terms of use or reuse permission, so the document is recorded here by
URL, version and sha256, and no copy of it enters the repository or the
cache. Its content is cited by section only.

## Artefacts

### `SOGIS-Agreed-Cryptographic-Mechanisms-1.3.pdf` (read, not redistributed)

- Source: <https://www.sogis.eu/documents/cc/crypto/SOGIS-Agreed-Cryptographic-Mechanisms-1.3.pdf>
- Version: SOG-IS Crypto Evaluation Scheme, Agreed Cryptographic Mechanisms, Version 1.3, February 2023 (SOG-IS Crypto Working Group)
- sha256: `5560ab5c86de3e62d63304c433691f5ad01116b88aceaea52a8e4b8887e0afb3`
- Licence: None stated: the document carries no copyright notice, licence or terms of use, and the SOG-IS supporting documents page (https://www.sogis.eu/uk/supporting_doc_en.html, read 2026-11-05) states no copyright, licence, terms of use or reuse permission
- Not redistributed: the owner read the file and its sha256 is recorded;
  the script copies it nowhere, and this repository carries none of its
  content.
- Note: Fetched from the URL on 2026-11-05 (382787 bytes, created 2023-02-16 by pdfTeX) and read for FerroHEALTH/FerroFED#1624. eHDSI Cryptographic Algorithms 9.0.0 §5.1 names this URL under the label "Version 1.4. January 2020", an editorial error: no 1.4 exists. The floor eHDSI reads from it is the "Legacy valid beyond 2025" level: RSA moduli of at least 3000 bits (§4.1 and Note 27), SHA-256 and above, PSS and PKCS#1 v1.5 signatures (§5.2), and no TLS 1.2 CBC suite.
