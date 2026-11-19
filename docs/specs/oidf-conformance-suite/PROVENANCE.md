<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the runner of the OpenID Foundation conformance suite

Vendored by `scripts/vendor/oidf-conformance-suite.sh`, each artefact pinned by its
URL and the sha256 of its bytes. Never edit a file here: change the pins in
the script and the pin-set digest in docs/VERSIONS.md, and re-run the script.

- Pin-set digest (sha256 over the sorted `mode  file  url  sha256` lines of
  the pins): `ac1b6b6a753a914418ddc08c0faa8c841e4a107aebdcc3471deb13280032c40a`
- Fetched: 2026-11-19, with the User-Agent `ferrohealth-smart-vendor (scripts/vendor)`
- Artefacts: 4 committed, 0 cache only, 0 needing
  manual retrieval
- Files in this directory: 4 besides this one, each verbatim as the
  publisher serves it
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `08bd02d1daa8ad59cd2627ae531a0fa765f8cb85045c3bf663ef4c449753b85d`
- Read by: the OpenID Foundation conformance lane (#621, `scripts/oidf/lane.sh`)

The runner script of the OpenID Foundation conformance suite
(<https://gitlab.com/openid/conformance-suite>) and the two Python modules it
imports, at the commit the release tag `release-v5.3.4` names, the release
whose image the lane runs. The files are executed unmodified and never read
as a specification.

## Artefacts

### `run-test-plan.py` (committed)

- Source: <https://gitlab.com/openid/conformance-suite/-/raw/23353b36957d6466010de767c812d2c91ed37638/scripts/run-test-plan.py>
- Version: release-v5.3.4, commit 23353b36957d6466010de767c812d2c91ed37638
- sha256: `6043f8fb9d64dcd30235540cae1f32eb4e94618d1fc5408f1e8ae626d6553ad2`
- Licence: MIT: the repository's LICENSE.txt, "This software is licensed under the MIT License: Copyright (c) 2019-2020 OpenID Foundation", vendored beside the files; it permits copying and distributing the software with the notice kept
- Note: The runner: it creates a test plan at a suite, runs each module, and for a relying party module runs the client under test.

### `conformance.py` (committed)

- Source: <https://gitlab.com/openid/conformance-suite/-/raw/23353b36957d6466010de767c812d2c91ed37638/scripts/conformance.py>
- Version: release-v5.3.4, commit 23353b36957d6466010de767c812d2c91ed37638
- sha256: `660214cc6ca9b3c09297f61908a575db7b1552e8f44eecd5740d1c27fa2cfca8`
- Licence: MIT: the repository's LICENSE.txt, "This software is licensed under the MIT License: Copyright (c) 2019-2020 OpenID Foundation", vendored beside the files; it permits copying and distributing the software with the notice kept
- Note: The client of the suite API the runner imports.

### `test_plan_parser.py` (committed)

- Source: <https://gitlab.com/openid/conformance-suite/-/raw/23353b36957d6466010de767c812d2c91ed37638/scripts/test_plan_parser.py>
- Version: release-v5.3.4, commit 23353b36957d6466010de767c812d2c91ed37638
- sha256: `2b00870b2dc46f1d44d047c715c0ef6978f24ece97a4a9d3b48ceeea8d01830f`
- Licence: MIT: the repository's LICENSE.txt, "This software is licensed under the MIT License: Copyright (c) 2019-2020 OpenID Foundation", vendored beside the files; it permits copying and distributing the software with the notice kept
- Note: The parser of the plan and variant syntax the runner imports.

### `LICENSE.txt` (committed)

- Source: <https://gitlab.com/openid/conformance-suite/-/raw/23353b36957d6466010de767c812d2c91ed37638/LICENSE.txt>
- Version: release-v5.3.4, commit 23353b36957d6466010de767c812d2c91ed37638
- sha256: `23dbf079b6fbcbf171c15aa2db3ff19dfd00863156c24c6813d5fe9617426352`
- Licence: MIT: the repository's LICENSE.txt, "This software is licensed under the MIT License: Copyright (c) 2019-2020 OpenID Foundation", vendored beside the files; it permits copying and distributing the software with the notice kept
- Note: The licence of the three files.
