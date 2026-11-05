<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Vendored inputs: fetched by a committed script, verbatim, with provenance

FerroAUTH vendors the specifications it implements under `docs/specs/`: the
SMART App Launch package and page sources, the OAuth 2.0 and JOSE RFCs, and
the OpenID Connect Discovery, Core and RP-Initiated Logout documents, each
tree with a `PROVENANCE.md`.

## Rules

- **Every vendored file is fetched by a committed script** under
  `scripts/vendor/` from the pin `docs/VERSIONS.md` records (a commit, an
  immutable publication or a checksum, never a moving tag or a `latest`
  URL), never copied by hand.
- **Vendored files are verbatim**: never edited. `scripts/checks/versions.sh`
  hashes every vendored byte back against its row and its `PROVENANCE.md`,
  so a hand-edited file, a moved pin or a stale provenance fails the pull
  request.
- **Every vendored tree carries a `PROVENANCE.md`**: the source, the pinned
  version, the date fetched, the licence, and how to refresh it. Vendored
  material keeps its upstream terms (CC BY 4.0 for SMART App Launch, the
  IETF Trust Legal Provisions for the RFCs, the OpenID Foundation's notice
  for the OpenID Connect documents, and each vendor document's own grant as
  its `PROVENANCE.md` quotes it).
- **A source whose licence forbids redistribution, or states none, is
  cache only**: its script pins the URL and sha256 (`scripts/vendor/lib/pinned.sh`,
  mode `cache`), fetches it into the git-ignored `.vendor-cache/`, and
  commits only its `PROVENANCE.md`, which records the licence as read and
  that no copy may be committed. `scripts/checks/versions.sh` fails when a
  copy reaches the tree.
- **A source behind a login is supplied by the owner**: its script
  downloads nothing, finds each file the owner placed in a local directory
  by the sha256 it pins (mode `supplied`) and commits it only when its own
  terms allow reuse. A file the owner read whose terms allow none is
  `withheld`: its sha256 and version are recorded, no copy is committed or
  cached, and it is cited by section only.
- **A new corpus or RFC** is a row in `docs/VERSIONS.md`, a fetch by the
  script and the citation that needs it, in one change.
- **Bumping a pin** is a deliberate change: rerun the script, read what
  changed against the citations in `docs/architecture.md` and the code, and
  record the new version in `PROVENANCE.md` and `docs/VERSIONS.md`.
- **No patient data and no credential** ever enters the tree under any
  name.
