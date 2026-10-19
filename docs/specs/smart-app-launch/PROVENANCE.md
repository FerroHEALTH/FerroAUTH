<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: SMART App Launch 2.2.0

Vendored verbatim by `scripts/vendor/smart-app-launch.sh`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Version: 2.2.0
- Publication: <http://hl7.org/fhir/smart-app-launch/STU2.2> (canonical `http://hl7.org/fhir/smart-app-launch`), the
  edition the package and the page sources below belong to
- FHIR versions: 4.0.1
- Author: HL7 International / FHIR Infrastructure
- Fetched: 2026-10-19
- Upstream licence: CC-BY-4.0, the `license` of `package/package.json`
  (Creative Commons Attribution 4.0 International,
  <https://creativecommons.org/licenses/by/4.0/>), which permits copying and
  redistribution in any medium with attribution. The repository carries no
  `LICENSE` file at the pinned commit, so the package's declaration is the
  one statement and this file is the attribution: SMART App Launch
  2.2.0 by HL7 International / FHIR Infrastructure, licensed CC BY 4.0, vendored unchanged.

## package/

The FHIR package `hl7.fhir.uv.smart-app-launch` 2.2.0 from the FHIR package registry
(<https://packages.fhir.org/hl7.fhir.uv.smart-app-launch>), extracted at its own layout.

- Registry sha1: `2e5b7caacf87523082507f6af2efdf25c24ad3d8` (the registry's `dist.shasum`,
  verified on the downloaded tarball)
- Tarball sha256: `0bb498dd09677684239f24d279b6da711cd814449f2f473c2970fbe881ec9c70`
- Built: 20240430191219 (`package.json` `date`)
- Declared dependencies: `hl7.fhir.r4.core` 4.0.1, `hl7.fhir.uv.extensions` 5.1.0-snapshot1, `hl7.terminology` 5.5.0
- Files: 33
- Package tree digest (sha256 over the sorted per-file `sha256  path`
  listing): `7078a64e5c6aca5e7d53d59bd1da597a186176d840670c59949495ecd0e5eb32`

It carries the ImplementationGuide resource, the CapabilityStatement, the
StructureDefinitions, the ValueSets and the CodeSystem the guide defines,
with its examples; the guide's prose is not in the package, which is why the
page sources are vendored beside it.

## repository/

The page sources of the guide from <https://github.com/HL7/smart-app-launch> at tag
`2.2.0`, resolved to commit `13449f93ba52d401d29ca9e72e8a4cbced8d6424` (2024-04-26T02:48:02Z), which predates the
package build, so these are the sources the publication renders. Each
`input/pages/<name>.md` renders as `<name>.html` under the publication
URL above.

- Pin: commit `13449f93ba52d401d29ca9e72e8a4cbced8d6424`
- Files: 35, of which 25 are `input/pages/*.md`
- Repository tree digest (sha256 over the sorted per-file `sha256  path`
  listing): `2756849598639150ba9a4f89a7b21e6f367586ce5c848670e47e439c755a2154`

The pages the design cites: `scopes-and-launch-context.md` (the scope
grammar and the launch context), `app-launch.md` (the launch flows and the
token request), `backend-services.md` (the client-credentials grant with a
signed assertion), `client-confidential-asymmetric.md` and
`client-confidential-symmetric.md` (client authentication),
`conformance.md` (the capability sets and the
`.well-known/smart-configuration` document) and `token-introspection.md`.
