<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the openEHR Reference Model Common chapter, development

Vendored verbatim by `scripts/vendor/openehr-rm.sh`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/openEHR/specifications-RM>, published at
  <https://specifications.openehr.org/releases/RM/development/common.html>
- Pin: commit `09e481e9f2ed9e3f9d5b9257bd68c0679d80c7cc` of the `master` branch (2026-11-02T00:52:44Z), the
  development RM that FerroHEALTH/FerroEHR generates from and
  FerroHEALTH/FerroBRIDGE vendors under the same path. The
  `manifest.json` of that commit lists no 1.2.0 release: the generation
  is unreleased.
- Fetched: 2026-11-05, each file from raw.githubusercontent.com at the commit
  and checked against the git blob id the commit records
- Upstream licence: Creative Commons Attribution-ShareAlike 3.0 Unported,
  as read in the repository's `LICENSE` file at the commit, vendored
  beside this file. The files are unmodified.
- Layout: the upstream paths of the commit, unchanged
- Files: 3
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `3b4b03456d283a9ab4300eda9afea7e093828f4c55e41c2442df884aff55d8db`
- Read by: the party states of the party binding (#216, #249), cited as
  openEHR RM Common §Abandoned and Inactive States

## What is taken

`docs/common/master06-change_control_package.adoc`, the Common IM chapter "Change Control Package", whose
"Version Lifecycle" section lists the lifecycle states (`800|inactive|`
and `801|abandoned|` among them) and whose "Abandoned and Inactive
States" section defines the two, with the component manifest. The other
chapters, the class definitions and the UML diagrams are not taken.

| File | sha256 | git blob id |
|---|---|---|
| `LICENSE` | `3f941b3b89cf7b8370ceb83cc76d2120d471b58735d8ca60238a751a48d7f72f` | `604209a804632b6e5274005a22293976d07c3099` |
| `docs/common/master06-change_control_package.adoc` | `b47497bea365432a064b036b5e9fc4350d467ada5a6b8c48b28d2ad749012d7e` | `8dc7ca392b7c656707259f9c6d6a29f2068c7255` |
| `manifest.json` | `34a1f45e6276b4c4616e15208e9555091b27057c609282600aad02c0d5e8f98d` | `3f7c0d95a92b630f3a2824a4660aeedaccb2bbd5` |
