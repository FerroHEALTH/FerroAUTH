<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the Inferno SMART App Launch test kit

Vendored verbatim by `scripts/vendor/inferno-smart-test-kit.sh`. Never
edit a file here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/inferno-framework/smart-app-launch-test-kit>
- Pin: tag `v1.0.3`, which resolves to commit `980e54e4ed632b28267d797013399a8588772174` (2026-09-03T11:42:33Z)
- Fetched: 2026-11-16, from the archive of the commit
- Upstream licence: the repository's `LICENSE`, the Apache License,
  Version 2.0, January 2004, vendored beside this file with its
  `NOTICE.md`. Its §4 permits reproducing and distributing copies of the
  work in any medium, with a copy of the licence and the NOTICE given to
  every recipient. The files are unmodified.
- Layout: the upstream paths, unchanged
- Files: 27
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `6023bdb214dc40c9f6685346235c37addd15ec0d00a5637a98280872ef15da1a`
- Read by: the FerroSMART step-1 research (#513) and the Inferno lane
  (#520), `docs/architecture.md` §13

## What is taken

- `lib/smart_app_launch/smart_stu2_2_suite.rb`: the SMART App Launch STU 2.2 server
  suite (`smart_stu2_2`), with its Standalone Launch, EHR Launch,
  Backend Services and Token Introspection groups.
- The group and test files that suite runs, from the STU 1 bases the STU 2
  and STU 2.2 groups extend to the Backend Services group.
- `lib/smart_app_launch/requirements/smart_app_launch_test_kit_requirements.csv`: the
  kit's extraction of each SHALL, SHOULD and MAY of SMART App Launch 2.0.0
  and 2.2.0 with its actor, and
  `lib/smart_app_launch/requirements/generated/smart_stu2_2_requirements_coverage.csv`,
  which maps each 2.2.0 requirement to the tests that check it.

The client suites, the User Access Brands suite, the presets and the
execution scripts are not taken.
