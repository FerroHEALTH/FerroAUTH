<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the IHE IUA Technical Framework Supplement

Vendored verbatim by `scripts/vendor/ihe-iua.sh`. Never edit a file here:
change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/IHE/ITI.IUA>, rendered at
  <https://profiles.ihe.net/ITI/IUA/index.html>
- Pin: tag `2.5`, which resolves to commit `a8e20c92928b7560ee07a410922187757248c8b9`
- Document: Internet User Authorization (IUA), Revision 2.5 - Trial Implementation,
  dated June 18, 2026
- Fetched: 2026-11-05
- Upstream licence: the repository's `LICENSE`, Creative Commons
  Attribution 4.0 International, vendored beside this file. The IHE
  Technical Frameworks General Introduction §9
  (<https://profiles.ihe.net/GeneralIntro/ch-9.html>) also grants every user
  of IHE Technical Documents a licence to reproduce and distribute them under
  IHE International's copyrights. The supplement reproduces no table of a
  base standard; it refers to OAuth 2.0 RFCs and HL7 FHIR by link.
- Layout: the upstream paths, unchanged
- Files: 13
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `f3f0f8b009071fdb702857519768b64e5b9ec4769dbcbafe133d5bd01fd4314a`
- Read by: #215 (the caller classification's reading of the ITI-71
  access token claims), vendored by #222

## What is taken

`IHE_ITI_Suppl_IUA.md` is the supplement's whole text: Volume 1 §34 (the IUA
profile) and Volume 2 §3.71 Get Access Token [ITI-71], §3.72 Incorporate
Access Token [ITI-72], §3.102 Introspect Token [ITI-102] and §3.103 Get
Authorization Server Metadata [ITI-103]. `media/` is the upstream
directory whole: the figures the text links and the slide deck the actor
diagrams are drawn in, which the text does not link but which is kept so
the directory stays as the publisher ships it. The repository's build
script, stylesheet, code system, issue templates and README are not taken.
The status is the document's own: a Trial Implementation supplement may be
amended before it is incorporated into the Technical Framework.

| File | sha256 | git blob id |
|---|---|---|
| `IHE_ITI_Suppl_IUA.md` | `af63d1ddfb5b908bc88d7c01490d56a036a7666145680171a71c8c95d2e83f95` | `e847a8ecb67aeafe1e16c6097d58b63367e07e02` |
| `LICENSE` | `9e5f1b3c610b9c2da5c313bf81d577a7d1acec686bdb0384edefa6df0f90cd94` | `4ea99c213c5c0c005ae4e80df8e52169d06896ec` |
| `media/1.0_IUA-actor-diagram.png` | `d0b1301faf6b2531449d56cd7f4eea064e4b649eba5d30b08a0db2f6a5029fce` | `9ebc7f27e70fe875c7117797d18626a6f16df936` |
| `media/1.1_IUA-actor-diagram.png` | `9002d86adb0a8bcbe97f8f229e59c693aaa55f3ffd1d444429488f52cf18d9c0` | `57c286e627e7851890d482c530bba28bdf9f72b5` |
| `media/1.2_IUA-actor-diagram.png` | `35b61c3f14961d1cbf155dfe8f8a769195e5f1fe8fd062e2687dbe9ecfa8184c` | `e70dca5f3213aa633aee4ef7fb7e9035798a27df` |
| `media/Actors.pptx` | `4f5e442c0e834e0dd9cac3a8b5cf419ce7e3ade0bc4f32610474c1bc9089f514` | `bfb48df74af09652680859bfa843ce2937d0932a` |
| `media/IHE-logo.jpeg` | `cf435f56b459a56790905268c416d24f26d100cdf81c0ac4e427e315c1e5b2c6` | `4459cc06a2d1d17beb0267a719344aeeaa3aadd9` |
| `media/authorization-code-grant.png` | `4ba1719104defb2b93a3ac605fc2b6abb51d8618fe60e127aa53ff8bf518ca3a` | `2e83fbdedc849b13004d9649cf4509b15a4662f7` |
| `media/basic-flow.png` | `c38ef7ce0f84aadcebe33ebd78246785e912fa32d2ab076f13eb16fa86f1e5ad` | `db9c5483626c8d15b6b1a0f00946ad919732b0ca` |
| `media/client-credential-grant.png` | `961a1b4c0ca1e88e547be1b0b465b094d48e4a4c591b0376245fc69967facc56` | `17ae456614ec99130d43f65e40003385840cae2f` |
| `media/get-authorization-server-metadata.png` | `2198221403eb9200be567e716fd02407c72da0a2256c32039a8b3b4a55e7d5b2` | `898a466ea3604087684a6b527eddef452aaee197` |
| `media/incorporate-token.png` | `e533a7e1d1a6d91bad16a6daefdce85cc4e6ec350585bc44f21e11f7c4bde438` | `157eadebc407f7bda04017256c156f35468dbf5d` |
| `media/introspect.png` | `c1b7ae8e2a233a1a73264d57ddc604bb5f020af7c957d897d16206797c784cc3` | `6ecc4ecb7ef0803252b85fca093bcddc72ad9115` |
