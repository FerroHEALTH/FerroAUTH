<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the SCIM workload identity federation guide

Vendored verbatim by `scripts/vendor/scim-workload-identity.sh`. Never
edit a file here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/AzureAD/SCIMReferenceCode>, the file `Workload-Identity-Federation-for-SCIM-Provisioning.md`
- Pin: commit `21b92c8f28383e30f8c304908b126682af2370d7` (2026-10-26T18:43:38Z)
- Document: "Workload Identity Federation: A New Authentication Method for
  SCIM Provisioning", dated 25th June 2026 in its own header
- Fetched: 2026-11-05, each file from raw.githubusercontent.com at the commit
  and checked against the git blob id the commit records
- Upstream licence: the repository's `LICENSE`, the MIT License
  ("Copyright (c) Microsoft Corporation. Permission is hereby granted, free
  of charge, ... to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute ...", on the condition that "The above copyright notice and
  this permission notice shall be included in all copies or substantial
  portions of the Software"), vendored beside this file. The files are
  unmodified.
- Layout: the upstream paths, unchanged
- Files: 8
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `2f8ed5e380aad089e3ab29bf2d85748ee285c2cad75bac00567bb8d105a87ae0`
- Read by: the RFC 7523 JWT bearer grant of #217, where Entra ID presents a
  workload identity assertion to an application's token endpoint, vendored
  by #222

## What is taken

The guide and every figure under `media/workload-identity-federation/`,
which it links. The reference code, the validation templates and the other
documents of the repository are not taken.

| File | sha256 | git blob id |
|---|---|---|
| `LICENSE` | `9906940f61b1f0b533fa7d99baf55178b2808fbe113ea51dfbfad8572ccd5f2b` | `3d8b93bc7987d14c848448c089e2ae15311380d7` |
| `Workload-Identity-Federation-for-SCIM-Provisioning.md` | `f60c5208637503ceed38a6a49aea11a6cee90049dafa8ad81e09676198d89d0f` | `677e0fbcc0a059cd453a59e34011236a4a5b8d30` |
| `media/workload-identity-federation/complete-entra-connectivity-settings.png` | `2a9988fb61dff1c3b998eaeaafa9090a080ecdacd6503a069443e7526f70bac6` | `d3b9142710b6affd5e15e4d0318b505911fef7b2` |
| `media/workload-identity-federation/copy-wif-claims-to-isv.png` | `0baec141aaf1de8fec9d3598b5a500844a793b46d135bb3d6700ef9cfde99583` | `8ef83d7249075086986ac223439f7198d9300718` |
| `media/workload-identity-federation/register-new-workload-identity.png` | `84e6ac8cbedfbd5c9d76df6457ebbc28a5678069c46129590ff3bf4d7bfdd70e` | `58a8cd858eec21d5b8ce8cd8421b6e62d2783ab4` |
| `media/workload-identity-federation/select-existing-workload-identity.jpg` | `37743d3d5580f8083ab21be24286bccb72de2560691b266646ab2072822550bf` | `16eb0d11f476d4a82b6571ce45f0a606cb1c1e60` |
| `media/workload-identity-federation/switch-to-workload-identity-authentication.png` | `8ea7bd817d2e45922f6f0921fa829c6141aa4078bf1b4b72e62e33c52de450f9` | `34437f3c81673a6fdfbfdcfcb05c1add9601b9ee` |
| `media/workload-identity-federation/wif-configuration-flow.png` | `f64c81ad3ef020f6a2a41cbc42f54ed26f40e0d8e8161b018e973dcd26d209b7` | `17f80a9e71fffced5c94f5f93611b5d15dfee36d` |
