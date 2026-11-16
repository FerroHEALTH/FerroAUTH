<!-- This file describes vendored material; the bytes beside it are copied
     verbatim and keep the licence their headers and LICENSE name. -->

# Provenance: the FerroBRIDGE Practitioner mapping

Vendored verbatim by `scripts/vendor/ferrobridge-practitioner.sh`. Never
edit a file here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/FerroHEALTH/FerroBRIDGE>
- Pin: tag `v0.0.26`, which resolves to commit `f3938c0aa20029b71fffeb3bd9766a2f0ffe33e9` (2026-11-16T18:52:07Z), the
  release whose image the Inferno lane runs
- Fetched: 2026-11-16, each file from raw.githubusercontent.com at the commit
  and checked against the git blob id the commit records
- Licence: the Business Source License 1.1 (`LICENSE`), the Licensor of
  this repository; the files are unmodified
- Layout: the upstream paths, unchanged
- Files: 4
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `cf28e926891b1d4e520a5419b2a6b3f05b72982241cdccddc27b1e47cf9a18b9`
- Read by: the Inferno lane (#520), which loads the template into FerroEHR
  and the two mappings into FerroBRIDGE so the facade serves the person's
  `fhirUser` as a `Practitioner`

## What is taken

- `tools/ferrobridge-testkit/fixtures/opt/person.opt`: the ADL 1.4 PERSON
  template `ferrobridge.person.v1`.
- `app/ferrobridge-server/tests/it/fixtures_demographic/ferrobridge_demographic_practitioner.context.yml` and
  `ferrobridge_demographic_practitioner.yml`: the FHIRconnect party
  context and model mapping of the base `Practitioner` onto it.

| File | sha256 | git blob id |
|---|---|---|
| `LICENSE` | `5327e1b1ac2378e89ceb7806be6efc7902a006c2ba7a28f7877da782f58d4ee3` | `e253ea3679f587b196727e6ab260ffb279fbea74` |
| `app/ferrobridge-server/tests/it/fixtures_demographic/ferrobridge_demographic_practitioner.context.yml` | `371b4d658cb6e70c0c83c16e1edc1d328ca167d0b506fdf7383094e8fad71dc3` | `e2cd61f249b12187fb3552d13bd7e32cf6e145c5` |
| `app/ferrobridge-server/tests/it/fixtures_demographic/ferrobridge_demographic_practitioner.yml` | `267f493efd351981c9a6748701f75b7940a4f84b38d275bac94c50bb544776df` | `80257101b4864163dece6e1e97a9f58502edacd6` |
| `tools/ferrobridge-testkit/fixtures/opt/person.opt` | `5ac0a4142a71c1fcfb504d6c351a10e87c4ab6babcf39b32bb65f7f49ac36214` | `10187b239057ab2c5a03fd9d32e0f09ba8e424da` |
