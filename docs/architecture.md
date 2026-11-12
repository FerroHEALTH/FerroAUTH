<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Architecture

FerroAUTH holds three crates: authentication, `ferrohealth-smart`, the
policy decision, `ferrohealth-authz` (section 11), and the console sign-in
and session, `ferrohealth-session` (section 12). Sections 0 to 10 design
`ferrohealth-smart`, the shared library with which every
FerroHEALTH product (FerroBRIDGE, FerroEHR, FerroFED, FerroPIX and FerroTERM) acts as an
OAuth 2.0 and SMART App Launch 2.x resource server, verifies and sends
machine-to-machine credentials, and writes one audit line per request. It is
the owner's decision of 2026-10-19, and this document is the design of
record. Every decision below names its ground in a vendored specification
(`docs/specs/`, pinned in `docs/VERSIONS.md`), and where no specification
governs a decision the text says so: "no specification governs this: our own
design". The product code the design replaces was read on each product's
`main` on 2026-10-19 and is named in section 5, so the migration is a list
of moves.

Citation style: `rfc6749 §4.4` is `docs/specs/rfc/rfc6749.txt` section 4.4;
`smart conformance` is `docs/specs/smart-app-launch/repository/input/pages/conformance.md`
(rendered as `conformance.html` under the STU 2.2 publication); `discovery
§4.3` is section 4.3 of `docs/specs/openid-connect-discovery/`; `soe
master08` is `docs/specs/smart-on-openehr/docs/smart_app_launch/master08-scopes.adoc`;
`rm-common master06` is
`docs/specs/openehr-rm/development/docs/common/master06-change_control_package.adoc`.

## 0. The picture

```text
                 inbound                                   outbound
  client ──Bearer/Basic──▶ product listener            product ──▶ upstream
                            │                                 ▲
                      AuthLayer (tower)                 BasicSender
                      ├─ Verifier (JWT)                 ClientCredentials
                      │    ├─ discovery (RFC 8414 / OIDC)   ├─ client_secret_basic
                      │    ├─ KeySet cache (RFC 7517)        ├─ client_secret_post
                      │    └─ token checks (RFC 9068)        └─ private_key_jwt
                      ├─ BasicVerifier (RFC 7617, Argon2id)       (RFC 7523)
                      ├─ Scopes (SMART App Launch 2.2)
                      └─ Audit (one line per request)
                            │
                       Access extension ──▶ product handlers (axum extractor)
```

One crate, four consumers. The library owns everything in the middle column:
it decides who the caller is and what the caller's grant reaches, and it
obtains and presents the product's own credential upstream. The product owns
the two edges: which route needs what (its route table and its interaction
model), what the refusal body looks like (an `OperationOutcome`, an ITS-REST
error body, a JSON document), and every policy beyond the SMART grant
(FerroEHR's roles and attributes, FerroFED's purpose of use and trust list).

## 1. The role: a resource server, never an authorization server

OAuth 2.0 names four roles: the resource owner, the resource server, the
client and the authorization server (`rfc6749 §1.1`). SMART App Launch has an
EHR system "operate as both resource servers and authorization servers"
(`smart conformance`, Actors). `ferrohealth-smart` takes exactly one of those
roles for every product: the resource server, which "SHALL validate the access token
and ensure that it has not expired and that its scope covers the requested
resource" (`smart app-launch`, Access FHIR API, Response; `smart
backend-services`, Access FHIR API, Response), plus the two client-side
credentials a product needs to call another server.

It never issues a token, never runs a login, and never holds a key that
signs an access token. The authorization server is the deployment's own, any
standards-compliant one, named by its issuer identifier; the product reads
its metadata and its key set and trusts what that server signed. The one
private key the library can hold is a client credential: the key behind
`private_key_jwt` signs the product's own client assertion to its
authorization server (`rfc7523 §2.2`), which is the asymmetric form of a
client secret and signs nothing a resource server would accept.

Why one library: the four products each carry their own copy of the same
checks today (section 7), with differences that are accidents of history
(which `typ` values pass, whether `nbf` is checked, whether the reason for a
refusal reaches the wire, how a refetch of the key set is bounded). A
security check that differs between products is a defect in at least one of
them. One crate, reviewed once, closes that.

## 2. Pinned versions

The single source of truth is `docs/VERSIONS.md`; this table carries the
grounds. `scripts/checks/versions.sh` compares the first token of each row
with the matrix.

| Item | Pin | Ground |
|---|---|---|
| SMART App Launch | 2.2.0 (STU 2.2, on FHIR R4 4.0.1) | The registry's `latest` on 2026-10-19 and the current 2.x publication; the 2.x line is where the `cruds` scope grammar, the `.well-known/smart-configuration` document and the asymmetric client profile live. Vendored as the package `hl7.fhir.uv.smart-app-launch` 2.2.0 and the page sources at the release tag. |
| IETF RFCs | RFC 6749, 6750, 7515, 7517, 7519, 7523, 7617, 7662, 8414, 8725, 9068, 9700, 8707, 7638, 9449, 8705, 9470, 8259, 6454, 7636, 7009, 7643, 9396, 7521, 7522, 8693, 3986 | None is obsoleted (the vendor script refuses an obsoleted pin). RFC 9700 updates 6749 and 6750 and RFC 8725 updates 7519, so each is read with its update. RFC 8707 is the `resource` parameter the client credentials client sends and RFC 7638 the thumbprint that names the product's own JWK. RFC 8705 §2 and §5 are the mutual-TLS client authentication of the token client (3.5), and §3 the certificate-bound tokens of 3.15. RFC 9470 is the step-up challenge of 3.7. RFC 8259 §4 is the repeated member name a metadata document is refused for, and RFC 6454 §4 and §5 the origin the opt-in endpoint check of 3.1 compares. RFC 7636 (PKCE) and RFC 7009 (token revocation) are the code exchange and the revocation of the `oidc` relying party. RFC 9449 (DPoP) is the proof-bound tokens of 3.15. RFC 7662 is in the set because section 6 says why introspection is not the default. RFC 7643 §2.4 and §4.1.2 are the SCIM `roles` and `entitlements` forms the role claims of 3.11 read. RFC 9396 (rich authorization requests, which SMART marks experimental) is the `authorization_details` a client grant sends and reads back (3.5); the resource server reads no `authorization_details` claim (3.11). RFC 8693 (token exchange, `act` in §4.1) and RFC 7521, the assertion framework that RFC 7523 profiles for the JWT bearer grant, with RFC 7522 its SAML 2.0 profile beside it, are the onward grants and the delegation of the caller classification (FerroHEALTH/FerroAUTH#215, #217). RFC 3986 §6.2.2 and §6.2.3 are the normalizations RFC 9449 §4.3 has a server apply before it compares the `htu` (3.15), and §4.2 the network-path reference the session's return path refuses (FerroHEALTH/FerroAUTH#235). |
| OpenID Connect Discovery 1.0 | incorporating errata set 2 (2023-12-15) | The edition the unversioned URL serves; RFC 9068 §4 names it as the alternative to RFC 8414 for publishing keys and the issuer. |
| OpenID Connect Core 1.0 | incorporating errata set 2 (2023-12-15) | The edition the unversioned URL serves; the authorization code flow (§3.1) and the ID Token check (§3.1.3.7) of the `oidc` relying party. |
| OpenID Connect RP-Initiated Logout 1.0 | final (2022-09-12) | The edition the unversioned URL serves; the end-session request (§2) and the `end_session_endpoint` metadata (§2.1) of the `oidc` relying party. |
| FAPI 2.0 Security Profile | Final Specification (2025-02-22) | The profile a client grant can be held to (3.5): the authorization servers of the Dutch BgZ and eOverdracht track FerroFED reaches follow it. §5.3.3.1 sets the client's sender constraint, client authentication, assertion `aud` and metadata use, and §5.4.1 the admitted algorithms. |
| Party binding references | IHE IUA Revision 2.5 (`IHE/ITI.IUA` tag `2.5`), Nuts RFC021 (`nuts-foundation/nuts-specification` at `7c0de533…`), the Microsoft Entra documents (`MicrosoftDocs/entra-docs` at `219d8d57…`), the SCIM workload identity federation guide (`AzureAD/SCIMReferenceCode` at `21b92c8f…`), Keycloak 26.8.2, and the Okta OpenID Connect and OAuth 2.0 API reference (cache only) | The access token of a federation issuer (IUA ITI-71, Nuts RFC021) and the deviations of each vendor profile from RFC 9068 (Entra ID, Keycloak, Okta) that the caller classification reads (FerroHEALTH/FerroAUTH#215). IUA and RFC021 are the editions FerroHEALTH/FerroFED vendors. The vendor documents are evidence for a profile's values, never the oracle for a core rule. The Okta page states "All rights reserved", so only its pin and provenance are committed. |
| Contact-point references | The eHDSI SAML Profile, Section II Security Services, Service Location and Capability Lookup Profile, NCPeH Components Specifications and Messaging Profile 10.0.0, the Cryptographic Algorithms 9.0.0, the X.509 Certificates Profile 7.0.0 and the Interoperability Specifications 8.0.1 (supplied by the owner); SOG-IS Agreed Cryptographic Mechanisms 1.3 (read, recorded by sha256, never copied); the MyHealth@EU Requirements Catalogue 10.0.0 (read, recorded by sha256, never copied); Implementing Regulation (EU) 2026/2099 and Regulation (EU) 2016/679 (the Official Journal XHTML); the Federation Tier with AQL specification 1.0.1 Annex B (`syntaric/openehr-federation-spec` at `b4242c29…`) | The contact-point issuer profile of the caller classification (FerroHEALTH/FerroAUTH#215): the IdA issuer, attributes, authentication classes, lifetimes and refusal names from the eHDSI documents, the fields of 2026/2099 Annex Tables 1 and 2, GDPR Art. 9(3) and Art. 29 for guests, and the Dutch `authorization_details` of Annex B §B.4a. The eHDSI files and Annex B are the ones FerroHEALTH/FerroFED vendors. The Requirements Catalogue states no reuse terms, so it is cited by section only. |
| Consent decision record | IHE Basic Audit Log Patterns (BALP) 1.1.4, the Volume 3 content page (3:5.7) as profiles.ihe.net renders it | The consent decision reference a `federation` token carries in `consent.reference` is the Consent entity of the 3:5.7.6 consent decision record (FerroHEALTH/FerroAUTH#286). The page is the one FerroHEALTH/FerroFED vendors. |
| SMART on openEHR | DEVELOPMENT (the ITS-REST draft, `openEHR/specifications-ITS-REST` at commit `9d25ea78…`, its tree last changed at `5183c1f9…`, amendment record 1.1.0 of 2025-05-20) | The one specification of openEHR scopes, which FerroEHR, FerroFED and FerroBRIDGE reach. It is a draft the ITS-REST release does not stabilise, so it is pinned by commit, its status is checked on every vendor run, and a weekly job fails when upstream moves (3.9). |

## 3. The components

### 3.1 Issuer discovery

The issuer identifier is configured. The library reads the authorization
server metadata at the RFC 8414 location first, formed by inserting
`/.well-known/oauth-authorization-server` between the host and the path after
removing a terminating `/` (`rfc8414 §3.1`), and on a `404` there at the
OpenID Connect location, formed by appending
`/.well-known/openid-configuration` to the issuer (`discovery §4.1`). Any
other status at the first location is final. The order and the fallback are
no specification's: our own design, the one FerroBRIDGE runs, chosen so an
authorization server that publishes only one of the two documents works
without a switch. RFC 9068 §4 requires the two documents to be consistent
where both exist, so the first that answers is read and the other is never
consulted.

The document must name the configured issuer exactly: "The `issuer` value
returned MUST be identical to the authorization server's issuer identifier
value into which the well-known URI string was inserted" (`rfc8414 §3.3`;
`discovery §4.3` has every operation that depends on failed validation
aborted). A mismatch refuses the start. The comparison is exact text, code
point by code point once the JSON escaping is removed, with no
normalization (`rfc8414 §4`), so a different case, a default port written
out or a terminating `/` is another issuer (`metadata::check_issuer`). A
product that also holds the configured issuer to the canonical form the URL
parser writes, without userinfo, so the text compared and the URL fetched
have one meaning, reads it with `metadata::canonical_issuer`; that form is
no specification's: our own design, FerroPIX's (#67).

A document in which any object repeats a member name is refused before it is
read (`DiscoveryError::RepeatedName`): "The names within an object SHOULD be
unique" (`rfc8259 §4`), and the meaning of a repeated one is each parser's,
so a second `issuer` or `jwks_uri` could be the one another reader takes.
The refusal is our own design (#69).

A product that sends a credential only to its issuer's origin opts into
`ServerMetadata::check_origin`, which refuses metadata naming an endpoint
(`jwks_uri`, the authorization, token, registration, introspection and
revocation endpoints, the mutual-TLS token alias) whose scheme, host and
port differ from the issuer's (`rfc6454 §4`, `§5`). RFC 8414 places no
endpoint, and an authorization server may publish its key set or an alias on
another host, so the check is off unless the product calls it: our own
design (#68).

The issuer is an `https` URL with no query and no fragment (`rfc8414 §2`,
`discovery §3` `issuer`), and the `jwks_uri` "MUST use the https scheme"
(`discovery §3`). One exception, no specification's: a loopback issuer
(`localhost`, `127.0.0.1`, `::1`) may be plain HTTP, because a test issuer is
one and its transport cannot be observed. FerroTERM runs this rule today;
FerroEHR's `allow_insecure_issuer` switch is replaced by it.

Discovery runs once at boot and refuses the start when the metadata or the
key set cannot be read: a server that cannot check a token must not serve a
surface it declares protected. A product that would rather start and answer
an unreachable issuer per request builds the server with
`ResourceServer::lazy`: the settings are checked at once, the metadata and
key set are read when the first token needs them, and a read that fails
answers that token `503` (3.7) and is not repeated inside
`jwks_refresh_interval`, the bound 3.2 sets on key set reads. No
specification governs when the key set is first read: our own design,
FerroFED's, moved into the crate (#55). Both constructors return `Send`
futures, so a product calls them from a request. The members read are `issuer`, `jwks_uri`,
`token_endpoint`, `authorization_endpoint`, `registration_endpoint`,
`introspection_endpoint`, `revocation_endpoint`, `grant_types_supported`,
`scopes_supported`, `response_types_supported`,
`token_endpoint_auth_methods_supported` and
`code_challenge_methods_supported` (`rfc8414 §2`; `discovery §3`). An omitted
`grant_types_supported` means `["authorization_code", "implicit"]` and an
omitted `token_endpoint_auth_methods_supported` means
`["client_secret_basic"]`, the documented defaults (`rfc8414 §2`, `discovery
§3`), never an empty capability.

### 3.2 The key set cache

The key set is the JWK Set at `jwks_uri` (`rfc7517 §5`): a JSON object with a
`keys` array; a member "that use[s] `kty` values that are not understood,
that [is] missing required members, or for which values are out of the
supported ranges" is ignored, as §5 says to, so such a member is legitimately
absent and no defect. A key is usable for verification when its `use`, if
present, is `sig` (`rfc7517 §4.2`), its `key_ops`, if present, holds `verify`
(`§4.3`), its `alg`, if present, equals the token's (`§4.4`), and its `kty`
belongs to the token's algorithm family. A symmetric key (`kty` of `oct`)
verifies nothing, whatever it says: see 3.3 on algorithms.

Key selection follows the token's `kid` header (`rfc7515 §4.1.4`, "used to
match a JWK `kid` parameter value"; `rfc7517 §4.5`). A token without a `kid`
verifies with the one usable key of its family when the set holds exactly
one; two or more candidates refuse the token, because taking the first would
let a rotation decide which key verifies a request. FerroTERM, FerroEHR and
FerroBRIDGE all refuse the ambiguous case today.

Rotation and freshness, no specification governs these: our own design.

- The set is read at boot, and read again when it is older than
  `jwks_max_age` (default `10min`), so a key the issuer withdraws stops
  verifying within that window without any token forcing a read.
- A token naming a `kid` the set does not hold reads the set again at most
  once per `jwks_refresh_interval` (default `60s`), because an unknown
  `kid` is how a rotation reaches the resource server; a stream of forged
  `kid`s cannot turn the product into a load on the authorization server.
  RFC 8725 §3.10 has the `kid` treated as untrusted input: it is compared
  as a string and never used to form a path or a query.
- Concurrent misses share one read; the write lock is held across the fetch.
- A read that fails keeps the previous set in use for the keys it holds and
  is not repeated inside the interval. A token that needs a key the held set
  lacks while the set cannot be read is answered `503`, never `401` and never
  admitted: the token was not checked, and the caller must be told to retry
  later, with the same token. This is fail closed: nothing is admitted
  on a failed read, and nothing is refused as invalid that was not examined.
- A `jku` or `x5u` header on a token is ignored: the keys come from the
  issuer's `jwks_uri` alone (`rfc9068 §4`, "MUST use the keys provided by the
  authorization server"; `rfc8725 §3.10` on following such URLs).

A key set may also come from a file (`jwks_file`) for keys handed over out of
band, FerroFED's need; such a set is re-read on the same schedule and is
never combined with a fetched one.

### 3.3 Token validation

A bearer token arrives in the `Authorization` header with the `Bearer` scheme
(`rfc6750 §2.1`), the scheme compared case-insensitively. A product behind
an edge proxy that forwards the credential in a header of its own names that
header (`Gate::with_credential_header`), either schemed like `Authorization`
or bare, its whole value a bearer token; the default stays `Authorization`,
and the rules below hold in whichever header is read (#56). Basic is read
from a schemed header only. The form-encoded
body parameter and the URI query parameter of `rfc6750 §2.2` and `§2.3` are
not read: a token in a query string reaches logs and browser history
(`rfc9700 §4.3.2`), and nothing in SMART needs either form. A request that
carries two credentials is `invalid_request` (`rfc6750 §3.1`).

The checks, in order, each a refusal when it fails:

1. **Structure.** The token parses as a JWS in compact serialization
   (`rfc7515 §5.2` steps 1 to 7; `rfc7519 §7.2`). A JWE is refused: no
   product negotiated encryption at registration, and `rfc9068 §4` has an
   encrypted token decrypted only with keys the resource server registered.
2. **Algorithm.** The header's `alg` is on the configured list, and the key
   that verifies it belongs to that algorithm (`rfc8725 §3.1`: "Libraries
   MUST enable the caller to specify a supported set of algorithms and MUST
   NOT use any other algorithms"; "each key MUST be used with exactly one
   algorithm"). The list holds asymmetric algorithms only. `none` is refused
   (`rfc9068 §2.1`, `§4`), and so is every HMAC algorithm, because a key the
   issuer publishes for verification would then also sign (`rfc8725 §2.1`,
   `§3.2`; the algorithm confusion of section 8). The default list is
   `RS256`, `RS384`, `PS256`, `PS384`, `ES256`, `ES384`: RS256 because
   "Authorization servers and resource servers conforming to this
   specification MUST include RS256 among their supported signature
   algorithms" (`rfc9068 §2.1`), RS384 and ES384 because SMART's asymmetric
   client profile names them (`smart client-confidential-asymmetric`,
   Registering a client), and the PS and ES256 forms because they are the
   current algorithms a deployment's authorization server is likely to
   mint. `EdDSA` is accepted when configured. A deployment narrows the list;
   it cannot add `none` or an HMAC.
3. **Type.** Under the default `rfc9068` profile the `typ` header is
   `at+jwt` or `application/at+jwt`, compared case-insensitively, and any
   other value is refused (`rfc9068 §4`, "MUST verify that the `typ` header
   value is `at+jwt` or `application/at+jwt` and reject tokens carrying any
   other value"). This is what keeps an ID token, a client assertion or a
   logout token from being spent as an access token (`rfc8725 §3.11`,
   `§3.12`). Under the `jwt` profile, for an authorization server that does
   not mint RFC 9068 tokens, `typ` may be absent or `JWT`; a value naming
   another kind is still refused, and the audience check below is what then
   keeps an ID token out, because an ID token's audience is the client, never
   the resource server. The profile is configuration, default `rfc9068`.
4. **Key and signature.** The key is selected as in 3.2 and the signature
   verified over the signing input (`rfc7515 §5.2` step 8).
5. **Issuer.** `iss` equals the configured issuer exactly (`rfc9068 §4`,
   "MUST exactly match"; `rfc8725 §3.8`), compared as a string with no
   normalization, because the metadata's `issuer` was already required to be
   identical to it.
6. **Audience.** `aud` contains one of the configured audiences, whether it
   is a string or an array (`rfc7519 §4.1.3`; `rfc9068 §4`, "MUST validate
   that the `aud` claim contains a resource indicator value corresponding to
   an identifier the resource server expects for itself"). A token without
   `aud` is refused (`rfc8725 §3.9`: "if the audience value is not present
   or not associated with the recipient, it MUST reject the JWT"). There is
   no unconfigured case: `audience` is required, and FerroTERM's "no
   audience configured, so `aud` is not checked" tolerance is not carried
   over.
7. **Time.** The current time is before `exp` and at or after `nbf`, each
   with the configured skew (`rfc7519 §4.1.4`, `§4.1.5`, "some small leeway,
   usually no more than a few minutes"; `rfc9068 §4`). `nbf` is checked when
   present, which is the opt-in the JWT crate needs. `iat`, when present, is
   not later than now plus the skew: no specification governs that check;
   our own design, because a token issued in the future is a clock the
   caller controls. The skew is `clock_skew`, default `60s`, at most
   300, the bound FerroFED fixes from the "few minutes" of RFC 7519.
8. **Required claims.** Under `rfc9068`: `iss`, `exp`, `aud`, `sub`,
   `client_id`, `iat` and `jti` are present (`rfc9068 §2.2`). Under `jwt`:
   `iss`, `exp`, `aud` and `sub`. A claim required by the profile but absent
   is a refusal, and a refusal names no claim on the wire (3.7). A `sub`
   that is empty or whitespace only is refused too: `rfc9068 §2.2` requires
   the claim, and `rfc7519 §4.1.2` has it identify a principal "locally
   unique in the context of the issuer", which a blank value does not. The
   gate holds the same rule over a caller any `Verifier` returns.

What the library then reads from a valid token: `sub`, `client_id`, `scope`
(the space-delimited string of `rfc6749 §3.3`, which `rfc9068 §2.2.3` carries
as the `scope` claim of RFC 8693), and `patient`. Two of these need a note:

- `scp`: some authorization servers mint the scopes as an array under `scp`.
  No vendored specification names it. FerroTERM reads it today. The library
  reads `scp` only when `scope` is absent, as an array of strings, and
  records that this is our own tolerance; section 9 asks the owner whether
  to keep it.
- `patient`: SMART places the patient of the launch context in the token
  response ("Launch context parameters come alongside the access token",
  `smart scopes-and-launch-context`, Launch context arrives with your
  `access_token`) and in the introspection response (`smart
  token-introspection`, Conditional fields), never in the access token
  itself, whose format SMART leaves to the issuer. A `patient` claim inside
  the token is therefore the issuer's own convention. The library reads it
  when present; a `patient/` grant without it reaches nothing (3.4). No
  specification governs the claim: our own design, which FerroBRIDGE runs
  today and FerroFED runs under the name `ehrId` for SMART on openEHR.

An access token's `jti` is read and carried but not tracked: see the replay
entry of section 8. A DPoP proof's `jti` is tracked (3.15).
Every other claim is passed over; a product that needs one (FerroEHR's `acr`,
FerroFED's IUA extension) reads it from the raw claims the `Access` carries,
under its own rules.

### 3.4 The SMART v2 scope grammar and its enforcement

The grammar is `smart scopes-and-launch-context`, FHIR Resource Scope
Syntax: `(patient|user|system)/(<FHIR Resource Type>|*).<permissions>`
with an optional `?param=value&…` suffix, and the permissions "a subset of
the in-order string `.cruds`". Each letter maps to interactions the same page
fixes:

| Letter | Interactions |
|---|---|
| `c` | type-level `create` |
| `r` | instance-level `read`, `vread`, `history` |
| `u` | instance-level `update` (an upsert included) and `patch` |
| `d` | instance-level `delete` |
| `s` | type-level `search` and `history`, system-level `search` and `history` |

The v1 suffixes are read as the page says servers SHOULD read them: `.read`
as `.rs`, `.write` as `.cud`, `.*` as `.cruds`. "Scope requests with
undefined or out of order interactions MAY be ignored": a permission string
out of order, repeated, empty or with an unknown letter grants nothing, and
so does a context other than the three, or a resource that the product's
type set does not name. Granting nothing is the safe reading: a scope the
grammar does not define can only refuse more than the issuer meant, never
admit more. The resource type vocabulary is the product's (FerroBRIDGE's R4
table, FerroTERM's R4B and R5 tables), supplied as a predicate; the library
pins no FHIR version.

Batch and transaction Bundles carry no scope of their own: "batch and
transaction requests should be validated based on the actual requests within
them" (Batches and Transactions). The library checks per entry, and the
product's handler calls it per entry.

**Granular scopes** (the `?param=value` suffix, the `permission-v2`
capability) are parsed and carried on the grant as a constraint, and the
library's own check admits such a grant only when the product supplies an
evaluator for the constraint. Without one, a constrained grant grants
nothing, which again refuses more and never less. The page marks modifiers,
chaining and `_filter` in the suffix experimental; the library parses the
`param=value` pairs and nothing more.

**Reach.** A `user/` or `system/` grant reaches every resource of the type
the product serves to that caller: "these scopes convey 'full access'
relative to the user's underlying permissions" (SMART's scopes are used to
delegate access), and the underlying permissions are the product's, applied
after the library (FerroEHR's roles, FerroFED's purpose of use). A `patient/`
grant reaches the compartment of the patient in the launch context, the
`patient` claim of 3.3: "If the app has any patient-level scopes, they will
be scoped to Patient 123" (Launch context arrives with your `access_token`).
A `patient/` grant on a token that names no patient reaches nothing. What a
patient's compartment is on an openEHR-backed server (the EHR the subject
maps to) is the product's own mapping; FerroBRIDGE keeps it in its
`compartment` module. When both a `patient/` and a `user/` or `system/`
grant cover a permission, the wider one wins, because scopes "can be combined
to represent a union of access" (Scope Equivalence).

**Other scope tokens.** `openid`, `fhirUser`, `launch`, `launch/*`,
`online_access` and `offline_access` grant no FHIR access and are passed
over. A product scope (FerroBRIDGE's `ferrobridge.operator`, FerroTERM's
`ferroterm/admin`) is a scope token the product names, and the library
answers "does this token carry scope *x*" so the product can gate a surface
no SMART scope covers; the page's Extensibility section is the licence for
such a scope ("use any string starting with `__`" or a full URI), and
section 9 asks the owner whether the two products' existing names move to one
of those forms.

**The scopeless-subject allowlist.** A token that carries no resource scope
of either grammar (this section's or the SMART on openEHR grammar of 3.9) is
admitted system-wide when its `sub` is on the deployment's allowlist, and
nowhere otherwise; `Caller::scopeless` reads the flag. No specification governs this: our own design, the
one FerroBRIDGE runs for an authorization server that cannot mint SMART
scopes for a service account. The allowlist is a list of exact subjects, and
a subject on it that does carry scopes gets only its scopes. A `sub` is
unique only within its issuer (`rfc7519 §4.1.2`), so an entry is
`{ issuer, sub }` and holds for that issuer's tokens alone, and only for a
`System` caller (3.14): a person, a patient or another party is never
admitted by it, and an entry naming a `patients` or `federation` issuer
refuses the start (4).

**A Basic principal** carries the scope string its configuration grants it
(4.1), so the same check serves a Basic caller and a bearer caller, and a
handler never asks which it was. No specification governs this: our own
design. A Basic principal is a person, so its configuration grants no
`system/` scope, a backend service's grant (`smart scopes-and-launch-context`):
an `[[auth.basic.users]]` entry holding one fails to load naming the user and
the scope, and `Caller::basic` drops any it is handed (#274).

### 3.5 Machine authentication

Machine-to-machine traffic has one form of its own, the OAuth 2.0 client
credentials grant, beside the onward grants a product uses on a caller's
behalf (3.16) and the tokens a `federation` issuer asserts (3.14). No
static bearer token and no API key exists in the family (owner decision
2026-10-19). HTTP Basic, verified and sent below, is a person's credential:
a Basic caller is classified `Person` (3.14), and a Basic user carries no
`system/` scope (3.4, #274; owner ruling 2026-11-05).

**Basic, verifying.** The credential is `Basic` followed by the base64 of
`user-id:password` (`rfc7617 §2`). The user-id "MUST NOT contain any control
characters" and a user-id "containing a colon character is invalid"; the
octets are decoded as UTF-8, the encoding the challenge advertises with
`charset="UTF-8"` (`rfc7617 §2.1`). A user is configured with the Argon2id
PHC string of its password (`password_hash` or `password_hash_file`) and the
scopes it holds; the cleartext is never stored and never logged. No
specification in the pinned set governs the hash: our own design, on the
OWASP Password Storage Cheat Sheet's Argon2id parameters
(<https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>),
which FerroEHR runs today with the `argon2` crate. An unknown user-id is
verified against a decoy hash of the same parameters, so the time a refusal
takes does not say whether the user exists (FerroEHR's enumeration defence,
carried over). Verification runs on a blocking thread, never on the async
runtime.

A verified credential may be kept for `[auth.basic] cache_ttl`
(default 0, none), so a repeat request skips the key derivation. The entry
is named by an HMAC-SHA-256 of `user-id:password` under a key drawn when the
store is built, never the password itself; only a credential that verified
is kept, so a wrong password always pays the derivation; the cache holds at
most 4096 entries. No specification governs the cache: our own design,
FerroEHR's, moved into the crate.

The outcome says whether a credential was admitted from the cache
(`Verified::cached`, `Caller::cached`), so a product that records each fresh
authentication records one per cache lifetime (#63).

**Basic, sending.** The outbound `[<lane>.credentials]` with `user` and
`password` renders the same header (`rfc7617 §2`), UTF-8 then base64, and
the credential type redacts itself in every `Debug` rendering.

**The client credentials grant.** The product obtains its own token with
`grant_type=client_credentials` posted form-encoded to the token endpoint
(`rfc6749 §4.4.2`, with the UTF-8 form encoding of Appendix B), with `scope`
when configured (`§3.3`). The token endpoint is configured outright or
discovered from the issuer as in 3.1. A configured `resource` is sent as
the resource indicator of `rfc8707 §2`, "an absolute URI" that names the
upstream the token is for, so the authorization server can restrict the
token's audience to it (`rfc9700 §4.10.2`); an `audience` parameter has no
specification and is sent only when configured, for an authorization server
that reads one in its place. The client authenticates one of three
ways, configured, never guessed from the server's metadata:

- `client_secret_basic`: HTTP Basic over the form-encoded client id and
  secret, "the HTTP Basic authentication scheme for authenticating clients
  that were issued a client password", which every authorization server
  MUST support (`rfc6749 §2.3.1`). The default.
- `client_secret_post`: `client_id` and `client_secret` in the body, which
  the same section calls NOT RECOMMENDED and limits to clients unable to use
  Basic. Supported for an authorization server that accepts nothing else;
  the parameters "MUST NOT be included in the request URI", and are not.
- `tls_client_auth` and `self_signed_tls_client_auth`: a client
  certificate in the TLS handshake, checked by the authorization server
  against its PKI or the client's registered keys (`rfc8705 §2.1`, `§2.2`),
  with `client_id` in the body, which "the client MUST include" (`§2`), and
  no secret. When the endpoint is discovered and a certificate is
  configured, the client posts to `mtls_endpoint_aliases.token_endpoint`
  when the metadata names it (`rfc8705 §5`, a MUST). A certificate may also
  be presented under the other methods, for an authorization server that
  binds the token to it. Extra trust roots for a token endpoint behind a
  private certificate authority are added to the built-in ones; a product
  may instead hand the client its own `reqwest::Client`, which is used as
  built, its redirect policy then the product's (#58).
- `private_key_jwt`: `client_assertion_type` of
  `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` with a single
  JWT in `client_assertion` (`rfc7523 §2.2`), the form RFC 9700 §2.5
  recommends ("It is RECOMMENDED to use asymmetric cryptography for client
  authentication") and SMART Backend Services requires (`smart
  backend-services`, Obtain access token). The assertion is the one `smart
  client-confidential-asymmetric` fixes: header `alg` (RS384 or ES384 by
  default, the two the profile mandates a client support), `kid` (required,
  unique in the client's set) and `typ` of `JWT`; claims `iss` and `sub` both
  the `client_id`, `aud` the token endpoint URL, `exp` "no more than five
  minutes in the future" (the library signs it valid for 60 seconds, since
  it is sent at once and some authorization servers cap the lifetime below
  five minutes: our own design) and a unique `jti`; one assertion per request,
  never reused (`rfc7523 §3` items 1 to 7). The `aud` is configurable:
  `token_endpoint`, the default and SMART's rule, or `issuer`, the
  configured issuer identifier, which `rfc7523 §3` item 3 also admits as "a
  value that identifies the authorization server", for an authorization
  server outside the SMART profile that asks for it (#59). The private key comes from
  `private_key_file`; the product serves the matching public JWK Set at a
  route of its own, which the library renders (`rfc7517 §5`, bare `n`/`e` or
  `crv`/`x`/`y` as the SMART profile requires), holding the current and the
  successor key during a rotation, the page's own advice. The `kid` of the
  product's own key is configured, or, when it is not, the SHA-256 JWK
  thumbprint of the key (`rfc7638 §3`), which names the key without a
  registry and changes with the key; the default is our own design, the
  thumbprint is the RFC's.

The response is read under `rfc6749 §5.1`: `access_token`, `token_type`
(`bearer`, compared case-insensitively; `rfc6750`; or `DPoP` for a grant
bound to a DPoP key, 3.15), `expires_in` and `scope`. SMART Backend Services makes
`expires_in` required and short ("SHOULD NOT exceed 300"), so the cache below
is sized for five-minute tokens. A non-`200` is read as the `rfc6749 §5.2`
error body (`error`, `error_description`, `error_uri`) when it is one, and
the refusal carries the status, the parsed error and the raw body: a token
the product could not obtain is a typed error, never a missing credential.

**The cache**, no specification governs it: our own design, FerroBRIDGE's.
One token per configured grant, fetched on first use, reused until
`refresh_margin` before `expires_in` (the margin capped at half the
lifetime), concurrent callers sharing one fetch, a token without
`expires_in` reused until the upstream refuses it. **One renewal on a
`401`:** when the upstream answers `401` to a request carrying the cached
token, the product invalidates that token, fetches once, and retries once;
a second `401` stands and reaches the caller as the upstream's refusal. A
token another caller already renewed is not fetched again.

**The key ring.** A `private_key_jwt` grant signs with the current key of a
`client::keys::KeyRing`, shared as an `Arc` with whatever else signs or
publishes with it. The ring renders its JWK Set (`rfc7517 §5`) in a fixed
order: the current key first, then the previous key while it stays
published (for an overlap window, or until the ring is rebuilt without it),
then the next key. Only the current key signs. Each key is published under
its configured `kid` or, by default, its `rfc7638 §3` thumbprint. A previous
key equal to the current key is refused, and so is a next key equal to
either. No specification governs the rotation: our own design, FerroFED's,
moved into the crate (FerroHEALTH/FerroAUTH#319).

**`authorization_details`.** A grant may send RFC 9396 `authorization_details`
on its client credentials request and its token exchange (`rfc9396 §6`).
The text goes out as written once it passes the `§2` shape check: a
non-empty array of objects, each with a non-empty string `type`, the `§2.2`
common fields in their stated types, and no repeated member name. When the
endpoint is discovered, every `type` must be listed in
`authorization_details_types_supported` (`§10`). A token response to a grant
that asked for details must state the details it granted, in the `§2` shape
(`§7`), and `IssuedToken::authorization_details` hands them to the product.

**The FAPI 2.0 Security Profile.** A grant whose `profile` is `Fapi2` is
held to the client rules of FAPI 2.0 §5.3.3.1 and §5.4.1 when it is built:

- an issuer it discovers from;
- `private_key_jwt` with the issuer as the one-string `aud`, or mutual TLS;
- every ring key and the DPoP key signing `PS256`, `ES256` or `EdDSA`;
- tokens bound by DPoP or the certificate;
- a `scope` or `authorization_details`, so the authorization server never
  chooses the token's reach (our own design);
- mutual-TLS alias hosts only on a grant that uses mutual TLS.

The metadata is held to the profile before anything reaches the token
endpoint:

- an `application/json` answer (`rfc8414 §3.2`);
- a token endpoint on the issuer's origin, or a mutual-TLS alias on a host
  the grant names (`rfc8705 §5`; the host list is our own design);
- the client's method and assertion algorithm listed (`rfc8414 §2`);
- `tls_client_certificate_bound_access_tokens` true for a certificate-bound
  grant (`rfc8705 §3.3`);
- each grant type it sends listed;
- the proof algorithm listed when `dpop_signing_alg_values_supported` is
  present (`rfc9449 §5.1`).

The authorization-endpoint rules of §5.3.2.2 need a user agent, and no
client grant has one.

**Never forwarded.** A caller's bearer token is never passed upstream. An
access token names the resource server it is for (`rfc9068 §4`, the `aud`
check that resource server runs), and "the resource server MUST treat access
tokens like other sensitive secrets and not store or transfer them in
plaintext" (`rfc9700 §4.9.3`). The product reaches its upstream under its
own credential, for the upstream's audience.

### 3.6 The audit line

One line per request that passes through the layer, written once the
response is ready, under the `tracing` target `ferrohealth_smart::audit` so
a deployment routes it apart from the application log. No specification
governs the line: our own design, shaped so it can serve as the access record
the products keep under Regulation (EU) 2025/327 Annex II 3.2(b), which asks
for "the specific natural person or persons having accessed" the data. The
field set is fixed; a product adds nothing to the line and removes nothing
from it, so the four products' records read the same:

| Field | Value |
|---|---|
| `at` | the arrival time, RFC 3339 in UTC |
| `request_id` | the request id the product minted or echoed, `-` when none |
| `principal` | the token's `sub`, the Basic user-id, `-` for an open route, `unauthenticated` for a refused credential |
| `client` | the client the issuer profile's client claims name, `-` when none |
| `kind` | the caller kind (3.14): `patient`, `system`, `delegated`, `representative`, `person`, `patient_representative`, `guest`, `external_person` or `external_organisation`, `-` for an open route or a refused credential; `scripts/checks/caller-kinds.sh` holds this list to `CallerKind::as_str` |
| `via` | `bearer`, `basic`, `open` or `none` |
| `issuer` | the issuer that signed the token, `-` otherwise |
| `binding` | what the login resolved to (3.17): `party`, `wrong_marker`, `unbound`, `ambiguous`, `inactive`, `abandoned`, `deprovisioned`, `key_claim_missing` or `groups_unavailable`, `source_unavailable` when the party source failed, `-` when no party binding looked the caller up |
| `party` | the party the outcome names, as `<namespace>/<type>/<id>`, `-` when it names none; never a name or another attribute of the party |
| `method` | the HTTP method |
| `route` | the matched route template, never the raw path |
| `addressed` | the product's name for what was addressed (`Condition/c-1`, `ehr/…/composition`), at most 64 characters, `-` when none |
| `interaction` | the product's name for the interaction (`read`, `search-type`, an ITS-REST operation id) |
| `status` | the response status |
| `duration_ms` | the time to the response |
| `entry` | the position of a batch or transaction entry, absent on a request line |

No field is named `target`, `level` or after another key a `tracing`
formatter writes from the event's metadata, so a JSON log that flattens the
event fields beside the metadata keeps all sixteen; the field was `target`
in 0.1.0 and is `addressed` from 0.1.1.

Never on the line: the token or any part of it, a claim beyond `sub`,
`client_id` and `iss`, a scope string, a query string, a header, a body, a
password, a client secret or a key. The `Debug` of every credential type
redacts itself, so a line cannot carry one by accident. A product that keeps
a further record (FerroEHR's ATNA audit, FerroFED's security log with its
HMAC references) keeps it beside this line.

### 3.7 The error model

The library returns a typed `Refusal`, and the product renders the body:
an `OperationOutcome` on a FHIR surface, the ITS-REST error body on an openEHR
surface, a JSON document on an admin listener. The renderer reads the
refused request's head (`http::request::Parts`), so a product answers in
the format the request negotiates (the `Accept` header, a FHIR `_format`). The status and the
`WWW-Authenticate` challenge are the library's and never differ by product.

- **No credential:** `401` with `WWW-Authenticate: Bearer realm="<realm>"`,
  and, when Basic is enabled on that surface, a second challenge
  `Basic realm="<realm>", charset="UTF-8"` (`rfc6750 §3`; `rfc7617 §2`,
  `§2.1`). No `error` attribute: "If the request lacks any authentication
  information …, the resource server SHOULD NOT include an error code or
  other error information" (`rfc6750 §3.1`).
- **A credential that does not hold:** one `401` for every cause, with
  `error="invalid_token"` for a bearer token, which `rfc9068 §4` makes a
  MUST "in case of any failure in the validation checks", and with no
  `error_description`. A bearer value outside the `b64token` syntax of
  `rfc6750 §2.1` is one such token, "malformed" in the words of `rfc6750
  §3.1`. The reason (which check failed) reaches the product as the typed
  `Reason` of the `Denied` that `Gate::authenticate` returns, for its own
  log, and nothing else: a refusal that names the failed claim teaches a forger
  which claim to fix next. No specification requires the omission: our own
  design. FerroTERM's `error_description` with the reason and FerroEHR's
  per-cause variants collapse into this one answer. A Basic credential that
  does not verify gets the same `401` and the same two challenges.
- **A credential that holds and does not permit:** `403` with
  `error="insufficient_scope"` and no `scope` attribute (`rfc6750 §3.1`
  makes the attribute a MAY). The body names no scope either, so a refusal
  teaches a caller nothing about the grants it lacks; no specification
  requires the omission: our own design, FerroBRIDGE's.
- **A `DPoP` request that does not hold** (3.15): `401` under the `DPoP`
  scheme, `error="invalid_dpop_proof"` for a proof that fails `rfc9449
  §4.3`, and `error="invalid_token"` for a token or a key binding that fails
  (`rfc9449 §7.1`, Figure 16), with no `error_description`. A surface that
  admits `DPoP` adds a `DPoP realm="<realm>"` challenge to the no-credential
  answer, after the `Bearer` one (`rfc9449 §7.2`, Figure 17).
- **Two credentials, or a malformed `Authorization` value:** `400` with
  `error="invalid_request"` (`rfc6750 §3.1`).
- **The key set or the metadata cannot be read when a token needs it:**
  `503`, never `401` (3.2). A product's own verifier whose upstream fails
  (an RFC 7662 introspection endpoint) reports it as `Rejection::Upstream`,
  which answers the same `503` (#57). No specification governs this status:
  our own design.
- **A credential that holds, from an authentication event the resource
  does not accept:** `401` with `error="insufficient_user_authentication"`
  and, when the product names them, `acr_values` and `max_age` (`rfc9470
  §3`), and no `error_description`. What a resource requires is the
  product's ("out of scope", `rfc9470 §3`); `StepUp::satisfied_by` checks it
  against the token's `acr` and `auth_time` (`rfc9470 §6`, `rfc9068 §2.2.1`)
  and `Refusal::StepUp` renders it (#60).
- **A route the product's classifier does not know:** `403` on a guarded
  deployment, so a route mounted without a classification fails closed. Our
  own design, FerroBRIDGE's.

Every challenge value stays inside the character set `rfc6750 §3` fixes for
`error` and `error_description`, and a realm is a configured string.

### 3.8 The `.well-known/smart-configuration` document

"FHIR endpoints requiring authorization SHALL serve a JSON document at the
location formed by appending `/.well-known/smart-configuration` to their
base URL", answered as `application/json` "regardless of `Accept` headers"
(`smart conformance`, Using well-known). The library builds the document from
the issuer's metadata and the capabilities the product enforces; the product
mounts it. The rules the builder keeps:

- `token_endpoint`, `grant_types_supported`, `capabilities` and
  `code_challenge_methods_supported` are required; `issuer` and `jwks_uri`
  are required only with `sso-openid-connect`, and `issuer` is "otherwise,
  omitted"; the rest is copied from the metadata when present (`smart
  conformance`, Metadata).
- `sso-openid-connect`, and with it `issuer`, is written when the issuer's
  metadata lists the `openid` scope in `scopes_supported` (an OpenID
  Connect issuer "MUST support the `openid` scope value", OpenID Connect
  Discovery 1.0 §3) or the product declares it, and never when the product
  withholds it (`SmartOptions::openid_connect`). It is written only when the
  metadata names a `jwks_uri`, which the capability also requires, so a key
  set read from a file never advertises it.
- `code_challenge_methods_supported` carries `S256` and never `plain`: "The
  `S256` method SHALL be included in this list, and the `plain` method SHALL
  NOT be included".
- `grant_types_supported` lists only `authorization_code` and
  `client_credentials`, and `token_endpoint_auth_methods_supported` only
  `client_secret_post`, `client_secret_basic` and `private_key_jwt`, each
  value kept only when the issuer advertises it, because those are "the
  options" the page defines and the document is the product's own assertion
  about itself.
- `scopes_supported` lists only scopes the product honours: "The server SHALL
  support all scopes listed here". It is RECOMMENDED, so the product fills
  it from `[auth] scopes_supported` (`Resolved::smart_options`), and the
  builder never copies the issuer's own list, which names scopes the
  issuer grants and the resource server may not enforce.
- `capabilities` holds the permission capabilities the product declares
  for its route table (`SmartOptions::permissions`, none by default, because
  a capability is one "that the server supports"; `permission-v2` only with
  a constraint evaluator), the client types and launch modes the issuer's
  metadata supports, `sso-openid-connect` as above, and what the product
  adds by configuration. A configured capability is one the page lists, one the
  SMART on openEHR draft lists (`soe master04`, Capabilities), or a full
  URI: "Simple, non-URI capability strings are reserved for definition in
  SMART App Launch", and other capabilities are "represented with full
  URIs" (`smart conformance`, Capabilities).

A resource server whose key set comes from a `jwks_file` reads no metadata,
so the operator supplies it (`ResourceServer::with_metadata`): it must name
the configured issuer, as `rfc8414 §3.3` holds a fetched document to, every
location it names follows the `https` rule of 3.1, and metadata read from the
issuer is never replaced. The builder is public
(`resource::configuration::document`) for a product that holds its metadata
elsewhere.

A product that trusts several issuers serves one document, so it describes
one of them: the `authorization_endpoint` is "Required if server supports the
launch-ehr or launch-standalone capability" (`smart conformance`, Metadata),
and every user launch starts there. SMART does not say which of several, so
the rule is our own design, one for every product
(`resource::described::describe`):

- **Eligible:** an issuer whose `kind` is not `machines` and whose metadata
  is available, read from it, introspected, or supplied by
  `with_metadata`. A `machines` issuer signs client credentials tokens only,
  and 3.14 refuses its every token that is not app-only, so no user launch
  works there. A `jwks_file` issuer without supplied metadata names no
  `authorization_endpoint`.
- **Named:** `[auth] described_issuer` must name an eligible issuer; an
  unknown, `machines` or metadata-less issuer is refused.
- **Unnamed:** the one eligible issuer is described; several are refused,
  naming them sorted and the key, and none is refused.

The order of the `[[auth.issuer]]` tables never decides, so an environment
overlay that adds an issuer cannot change the described issuer.

The route stays public: a client reads it before it holds a token. For an
openEHR surface the builder adds the `services` map and the openEHR
capabilities of 3.9, from the product's declaration of its base URLs.

### 3.9 The SMART on openEHR grammar

FerroEHR, FerroFED and FerroBRIDGE all reach openEHR resources: the first two
serve the ITS-REST surface, and FerroBRIDGE requests openEHR scopes for its
own CDR token. The crate therefore parses and enforces the SMART on openEHR
scope grammar beside the FHIR grammar of 3.4. The source is the ITS-REST
"SMART on openEHR" document, status DEVELOPMENT, vendored at
`docs/specs/smart-on-openehr/docs/smart_app_launch/` and cited here as
`soe master08` for `master08-scopes.adoc` and so on.

**The grammar** (`soe master08`, Resource Scopes): `<compartment>/<resource>.<permissions>`,
the compartment one of `patient`, `user` and `system` with the same meaning
as in 3.4, the resource one of three families with a pattern,
`template-<templateId>`, `composition-<templateId>` and `aql-<queryName>`,
and the permissions the letters `c`, `r`, `u`, `d` and `s`, with `s` "Search
or execute (e.g., for AQL queries)". A pattern is an exact id, `*::Name.v0`
(one name in any namespace), `Namespace::*` (any id in one namespace), or
`*` for "All available templates or queries"; `*` and `**` are both named
as wildcards. **The launch context** (`soe master07`, Context Selection):
`launch/patient` asks for "both FHIR `Patient` resource and corresponding
openEHR `EHR` instance", and the token response then carries `ehrId`, "the
unique identifier of the openEHR `EHR` instance"; `launch/episode` and
`episodeId` are experimental (`soe master09`). **The discovery document**
(`soe master04`): served relative to the platform base URL, with the FHIR
members unchanged, a `services` map keyed by reverse domain name in which
`org.openehr.rest` with its `baseUrl` is required and `org.fhir.rest`
recommended, and the capabilities `context-openehr-ehr`,
`openehr-permission-v1`, `launch-base64-json` and, experimentally,
`context-openehr-episode`.

**The parser is this crate's.** `ferrohealth_smart::openehr::smart_scopes`
is a total parser of this grammar (`SmartScope`, `ResourceScope`,
`Compartment`, `ResourceFamily`, `Pattern`, `Permissions`), the one every
product reads the grammar with: a second copy would fork the grammar
between the products, which is the drift one crate exists to close. It
moved here from FerroEHR's `openehr-sdt` with the same path and API
(owner decision 2026-10-27): a `0.0.x` requirement on that crate is exact,
so each of FerroEHR's lockstep releases left this crate behind and a
product resolved two copies. It depends on nothing beyond `std`, behind
the `openehr-scopes` feature, and for the browser (`wasm32-unknown-unknown`)
it is the whole crate, so a browser client (the FerroEHR viewer's scope
previewer) parses with the code the resource server enforces with (5). What the `openehr` feature adds is the enforcement: a `Requirement::OpenEhr {
family, permission, resource }` the product's classifier names per route,
checked against the token's parsed scopes.

**Where the draft is silent, these rules are ours**, carried over from
FerroFED's `auth/permission/grant.rs`, which moves into the crate with
FerroFED's migration:

- The permission letters are read in any order: the draft lists the five
  letters and fixes no order, unlike SMART App Launch, so `.rs` and `.sr`
  are one grant. A letter outside the five grants nothing.
- `*` matches within one `::`-delimited segment and `**` across segments;
  a bare `*` or `**` matches every id. The draft's table shows the four
  forms and no more, so this is the one reading under which every row of
  the table holds.
- A resource with no family of its own (the `EHR`, its `EHR_STATUS`, its
  `DIRECTORY`, a `CONTRIBUTION`) is held to the `composition-` family with
  the operation's permission over every template, because they are the EHR's
  data and the draft names no other family for them. The DEMOGRAPHIC API has
  no family either and no scope covers it: only a client the product lists
  by `client_id`, or a Basic principal it lists by user-id, reaches it
  (`Requirement::Client`, each list matched only against its own scheme).
- Where the product cannot see which resource a request addresses (an ad hoc
  AQL query, a composition whose template only the node knows, an upload
  whose template is in its body), only a pattern covering every resource,
  `*` or `**`, covers it; a specific pattern cannot be shown to match.
- `system/aql-*` counts only for a client the product lists as a backend
  client, because the draft's own note says it "would grant access to all
  registered and ad-hoc AQL queries system-wide".
- A `patient/` grant reaches only the EHR of the launch context: the `ehrId`
  the draft places in the token response, read from an `ehrId` claim in the
  token when the issuer carries it there (the same convention as `patient`
  in 3.3, our own design), and it "means nothing outside the platform that
  issued it", so a product honours it only for an issuer it binds to its own
  EHR space. It reaches EHR data alone: a `composition-` grant or an `aql-`
  search, never a `template-` grant.
- The FHIR v1 suffixes (`.read`, `.write`) are not applied to this grammar;
  the draft defines none.
- The two grammars coexist in one `scope` claim: each parser reads the
  whole claim and keeps its own grants, and a token may carry both
  `system/Observation.rs` and `system/composition-*.rs`. A scope string that
  parses in neither grammar grants nothing in either.
- The scopeless-subject allowlist of 3.4 holds here too: a subject on it
  whose token carries no resource scope of either grammar meets every
  `Requirement::OpenEhr`, and one whose token carries a resource scope of
  either grammar gets only its scopes, on this grammar's routes and on the
  FHIR grammar's alike.

**Which grammar applies to which route is the product's declaration**, not
the listener's: the classifier of section 5 names a `Requirement` per route, and the
requirement carries the grammar. `Requirement::Fhir { permission,
resource_type }` is checked against the 3.4 grants and
`Requirement::OpenEhr { family, permission, resource }` against this
section's, so a product that serves both surfaces under one listener
(FerroFED's facade beside a FHIR endpoint, FerroEHR's ITS-REST beside its own
FHIR surface) mixes them route by route, and a product that serves one
grammar declares one. Neither grammar is a configuration switch; the route
table is the declaration, and a route with no requirement is refused (3.7).

**The development status is handled by pinning and tracking.** The draft is
vendored at a commit, `scripts/vendor/smart-on-openehr.sh` refuses a tree
whose `manifest_vars.adoc` no longer declares DEVELOPMENT, and its
`--upstream` mode, run weekly by the `smart-on-openehr-upstream` job of
`.github/workflows/specs.yml`, fails when the repository's default branch
has a newer commit touching the tree. A change upstream is then re-vendored
and recorded as a decision in section 9, naming what changed and what the
crate does about it; nothing in the crate follows the draft silently, and a
rule above that the draft later settles differently is changed with its
tests and its decision row, never by drift. The crate's tests cite the
section names of the vendored draft, so a re-vendor that moves a section
fails a citation before it fails a behaviour.

### 3.10 Token introspection

An authorization server that issues tokens a resource server cannot read
itself is checked by OAuth 2.0 Token Introspection (`rfc7662`), behind
`[auth] mode = "introspection"` and the `fetch` feature
(`resource::introspection::Introspector`, a `Verifier` like the JWT check).
The issuer's metadata is read once at boot, as 3.1 reads it, and names the
`introspection_endpoint` unless the section does; the endpoint is held to the
`https` rule of 3.1, since the token travels in the request (`rfc7662 §4`
requires TLS).

The token is posted as `token` with `token_type_hint=access_token`
(`rfc7662 §2.1`) under the product's own credential, which §2.1 requires:
either the client authentication of the token endpoint (`rfc6749 §2.3.1`,
`rfc7523 §2.2`, `rfc8705 §2`, the same code the token client of 3.5 runs;
§4 names it as a common credential), or a bearer token the product obtains
with the client credentials grant, the form SMART has an EHR accept
(`smart token-introspection`, Authorization to perform Token
Introspection), renewed once on a `401`. A `private_key_jwt` assertion
names the introspection endpoint as its `aud`, or the issuer when the grant
asks for it (`rfc7523 §3` item 3 admits a value that identifies the
authorization server; the choice is our own design).

The response is read under these rules, each refusal the generic `401` of
3.7 with its own `Reason`:

- A body that repeats a member name (`rfc8259 §4`, as 3.1 refuses a
  metadata document), is no JSON object, or has no boolean `active`, and a
  status other than `200` (`rfc7662 §2.3`), are an upstream failure: `503`
  through `Rejection::Upstream`, never a refusal of the caller.
- `active` other than `true` refuses the token (`Reason::Inactive`,
  `rfc7662 §2.2`).
- `scope`, `client_id` and `exp` must be present (`smart
  token-introspection`, Required fields: "SHALL be included").
- `exp` and `nbf` are checked within the clock skew, though the
  authorization server already did (`rfc7662 §4`); the check costs nothing
  and a stale cache entry cannot outlive it.
- `iss`, when present, must be the configured issuer as exact text (3.1),
  and `aud`, when present, must name a configured audience. Both are
  optional in `rfc7662 §2.2`, and §4 has the authorization server determine
  whether the token "can be used at the resource server making the
  introspection call", so an absent one is admitted.
- A `token_type` is `DPoP` exactly when the response names a `cnf.jkt`,
  and otherwise absent or `Bearer` (`rfc6750`; `rfc9449 §6.2`); any other
  value refuses the token. The response's `cnf` is then held to the
  request's binding on every request, a held response included (3.15).
- A response without `sub` is the client's: "the value of sub SHOULD
  correspond to an identifier the authorization server uses to indicate
  the client application" when no resource owner is involved (`rfc9068
  §2.2`), so the subject is `client_id`; a blank `sub` is refused as 3.3
  refuses it.

The claims then go through the step the JWT check of 3.3 ends with (`iat`
within the skew, the subject, the scope parsed under the product's resource
table, `client_id`, the `patient` launch context, the whole response kept as
the caller's claims), so a product's handlers and the audit line read an
introspected caller as they read a JWT one.

An active response is held, keyed by the SHA-256 of the token so no token
stays in memory, until its `exp` and never longer than
`cache_max_age` (default `60s`): "the response MUST NOT be cached
beyond the time indicated" by `exp` (`rfc7662 §4`), and the age bounds the
window in which a revoked token still passes, the trade-off §4 leaves to the
deployment. Zero caches nothing. At most `cache_capacity` responses are held;
a full cache drops its expired entries, then the one that expires first. An
inactive response is never held, so a token activated later is not refused
from the cache. A caller admitted from the cache reports `cached()`. The
cache bounds are no specification's: our own design (FerroBRIDGE #533).

### 3.11 Roles and role requirements

RFC 9068 §2.2.3.1 has an authorization server that puts authorization
attributes in a JWT access token use the `groups`, `roles` and
`entitlements` attributes of the SCIM `User` resource (`rfc7643 §4.1.2`) as
claim types. `Caller::roles()` holds what the configured claims carry
(each `[[auth.issuer]]` names its own `role_claims`, by default those
three; a dotted path such as `realm_access.roles` reaches into a JSON object
for an issuer that nests them), so a claim is read from that issuer's
tokens alone, and a `federation` issuer contributes no role. A value is an array element that is a string, an element that is an
object with a string `value` sub-attribute (a SCIM multi-valued attribute,
`rfc7643 §2.4`), or each whitespace-separated word of a string. A role keeps
the issuer's spelling, trimmed, and appears once. An introspection answer is
read the same way (`rfc7662 §2.2` lets it carry further members). A Basic
user's roles are `[[auth.basic.users]] roles`, each one word.
`Caller::claim_text` reads a string at a dotted claim path for a product's
own attribute.

A route table states its role rules beside its scope rules:
`Requirement::Role` (the caller holds the role), `Requirement::AnyRole`,
`Requirement::WithoutRole` (a restriction, such as a read-only role on a
write, that overrides every grant combined with it) and `Requirement::All`,
beside the existing `Either`. Neither RFC gives roles a vocabulary or a
comparison rule, so a role is matched without regard to ASCII case: no
specification governs role semantics, our own design. RFC 9396 (rich
authorization requests) is vendored as the reference for the
`authorization_details` claim a later release may read; this one does not.

### 3.12 Assurance

RFC 9470 §3 lets a resource server refuse a token whose authentication does
not meet its requirement, with `401`, `insufficient_user_authentication` and
the accepted `acr_values`, and leaves the logic that decides it out of scope.
`assurance::AssuranceSection` holds that logic for every product, on each
`[[auth.issuer]]` table, since each issuer writes its own values: the claim
the class is read from (`acr` by default, OpenID Connect Core 1.0 §2), the
level each value stands for (low, substantial, high), and the minimum. The
issuer assesses each token when it admits it (`Caller::assurance`), and
`step_up` builds the `Refusal::StepUp` naming the values that meet the
minimum. Which routes a product holds to them stays the product's. The level
mapping is the deployment's: no specification governs it, our own design.

### 3.13 The natural person's own access

The EHDS person-access rights (Regulation (EU) 2025/327 Art. 5 and 9) need
every product to tell the same way whether a request is the natural
person's own access. SMART names *what* a `patient/` scope reaches and not
*who* asks (`smart scopes-and-launch-context`, Patient-specific scopes), so
the answer is the issuer's kind (3.14): `Caller::is_the_person` holds for a
`CallerKind::Patient` caller alone, a token of a `patients` issuer whose
scopes are `patient/` with no `user/` or `system/` grant (SMART on openEHR
`master08-scopes`, the `patient` context). A token of any other issuer is
never the person's, whatever scopes it carries: a `persons` token whose only
clinical scopes are `patient/` is a professional confined to its launch
context. A Basic caller is never the person. `Caller::person` returns the
patient the request is bound to: the `patient` launch context, the `ehrId`
and the patient claim's value. The deployment names its patient claim as a
`resource::PatientClaim`, a dotted path, attached to each resource server
with `with_extension`, the one extension the crate reads.

### 3.14 The caller classification

Every product needs one answer to who stands behind a token, and RFC 9068
§2.2 gives it only as a SHOULD (`sub` names the resource owner, or "an
identifier the authorization server uses to indicate the client
application"), with §5 describing an issuer that "elects to use the
client_id as the sub value". So the answer is read from the issuer, in three
layers, all in `ferrohealth-smart`:

1. **A generic core**, `kind`, defined by the standards only: RFC 9068 for
   the token shape, RFC 8693 §4.1 for an actor (`act.iss` with `act.sub`,
   prior actors "informational only"), OpenID Connect Core 1.0 §5.7 for the
   stable key (`email`, `phone_number`, `preferred_username` and `name` are
   never a key). No core rule names a vendor, and an integration test scans
   the core modules for a vendor's name.
2. **Vendor profiles as data**, `profile`: each issuer's `Profile` is a
   `Preset` (`rfc9068`, `entra`, `keycloak`, `okta`, `nl`, shipped as
   `profiles/*.toml` with each value labelled by its source) with any key set
   over it on the issuer table. The keys: `person_key`, `tenant_claim`,
   `client_claims`, `app_only` and `guest` (markers), `impersonation_marker`,
   `expect`, `user_claims` (claims every token that is not app-only must
   carry), `person_equality`, `unstable_claims`, `first_party_clients`,
   `delegates` (actors by `{ sub, issuer }` and clients by `{ client }`),
   `max_actor_chain`, `representation`, `token_types`, `required_claims`,
   `scope_claim` and `app_only_scope_claim`, and `adapter`.
   The `keycloak` preset names no impersonation marker: Keycloak 26.8.2
   (`con-protocol-mappers.adoc`) carries an impersonation as the session
   notes `IMPERSONATOR_ID` and `IMPERSONATOR_USERNAME`, not as a claim, so
   the operator maps `IMPERSONATOR_ID` into a claim with a User Session Note
   mapper and names that claim in `impersonation_marker`. A live case behind
   `FERROHEALTH_KEYCLOAK_E2E=1` starts the Keycloak image `docs/VERSIONS.md`
   pins, obtains its tokens at test time and classifies them; no token is
   committed. CI's nextest job runs it on every pull request that touches
   the profiles or the resource server.
3. **Vendor adapters as code**, only where data cannot express the
   behaviour, each an optional Cargo feature behind the
   `party::adapter::IdpAdapter` trait (3.17), in the `idp` tree, the one
   place outside the preset selector where a vendor's name stands. A
   profile names an adapter by its feature name, and a name this build does
   not compile in refuses the issuer at load, naming it
   (`ProfileError::Adapter`). The one adapter is `idp-entra` (3.17).

Each `[[auth.issuer]]` declares its `kind`, with no default: `persons`,
`patients`, `machines` or `federation`. A valid token is classified in this
order, and a token that matches no step for its issuer's kind is refused as
`Rejection::Unclassified`, an `invalid_token` on the wire whose
`kind::Unclassified` reason names the step:

1. `Patient`: a `patients` token naming only the record subject. One that
   carries an RFC 8693 §4.1 `act` is `PatientRepresentative` on an issuer
   whose profile sets `act_represents_patient = true`, with the top-level
   actor's `iss` and `sub` (a nested `act` is informational and never
   read), and is refused as `Unclassified::PatientActor` on any other, so
   a representative's access is never the patient's own (Regulation (EU)
   2025/327 Art 4(2) lets a natural person authorise others to act for
   them). `act_represents_patient` on another kind of issuer refuses the
   issuer at load.
2. `System`: the profile's app-only markers all match (they must agree, or
   the token is refused), on a `persons` or `machines` issuer.
3. `Delegated`: an `act` whose actor is a declared delegate (a chain deeper
   than `max_actor_chain` refused), or a third-party client that is a
   declared delegate.
4. `Representative`: a token of a `persons` issuer that declares
   `representation` and carries its claim, with the represented subject and
   the ground as asserted; with an `act`, or through a delegate client, it is
   refused, and `representation` on another kind of issuer refuses the
   issuer at load.
5. `Person`: a token of a `persons` issuer through a first-party client.

Before the steps, a token missing an `expect` value or carrying the
impersonation marker is refused, and a user token missing a `user_claims`
claim is refused naming it. A `persons` token with no client claim, or with a
client outside both lists, is refused; the client is always recorded
(`Caller::client_id`). A guest marker wraps the kind as `Guest`, which a
product admits only by a setting of its own. A Basic credential is a
person's and always a `Person`, never a `System` (owner ruling of
2026-11-05): a machine authenticates with the client credentials grant
(RFC 6749 §4.4). The scopeless allowlist (3.4) admits only a `System`
caller, the audit line records the kind (3.6), and `Caller::person_key` and
`Caller::tenant` carry the profile's key and tenant values.

How callers are classified is our own design over those sources.

**A `persons` issuer's professional attributes.** One `[[auth.attributes]]`
table per `persons` issuer (`federation::person::AttributesSection`) maps
the same fields the `federation` kind reads to their sources, a claim path
or a constant; `mapping = "iua"` reads the IHE IUA §3.71.4.2.2.1.1 claims
under `extensions.ihe_iua` (`subject_name`, `subject_role`,
`national_provider_identifier`, `subject_organization_id`,
`subject_organization` and `purpose_of_use`, never `person_id`), and
`authorization_details_purposes = true` adds the `purpose_of_use` of each
RFC 9396 `authorization_details` entry, written `system|code`. Every caller
of the issuer but a `System` carries what its token states as
`Caller::attributes`: the fields, the roles and the purposes of use as
codings, the purposes sorted and without duplicates. The purpose of use is
a property of the request, so a `System` caller of the issuer carries its
purposes alone, and a `patients` or `machines` issuer may have a table too,
which names no field but `purpose_of_use` and gives every caller, the
patient's representative included, its purposes alone (#438). A coding
whose `code` is empty names no code and an empty `system` no system (FHIR
R4 datatypes.html: `code` and `uri` have at least one character), so a
`purpose_of_use` of empty codes states none. An absent claim is an
absent field; a claim of no attribute shape, a `subject_role` or
`purpose_of_use` that is no array of codings (IUA: "shall be formatted as
array of FHIR Coding"), and a value with a control or bidi-control
character or past its cap refuse the token as `Unclassified::Attribute`,
naming the field. A table naming no trusted `persons`, `patients` or
`machines` issuer, two tables of one issuer, a field other than
`purpose_of_use` on a `patients` or `machines` issuer, and an
`authorization_details` or presentation source refuse the start. Which claims are read is our own design over IUA and RFC 9396.

**The `federation` kind.** A `federation` issuer's tokens name another
party's professional or organisation, and its one `[[auth.federation]]`
table (`federation::FederationSection`) maps each field, named after the
Commission Implementing Regulation (EU) 2026/2099 Annex Tables 1 and 2, to
its sources: a claim path (`mapping = "iua"` reads the IHE IUA
§3.71.4.2.2.1.1 claims under `extensions.ihe_iua`, and never `person_id`,
the patient's), a constant, a path in the RFC 9396 `authorization_details`
entry of the declared type, which counts only from an issuer declared to
attest it and only when its `locations` names this node, or a credential
subject path in the Verifiable Presentations of a Nuts RFC021 §6
introspection response. Strings are compared exactly, with "no additional
transformation or normalization" (RFC 9396 §12), and two sources that
disagree refuse the token. A token that names a professional (a
professional field, or `sub` other than the client) is a
`CallerKind::ExternalPerson` only with every Table 1 field, the name as one
string or as family and given names, and is refused as
`ExternalIncomplete` naming each missing field otherwise. One that names
none is an `ExternalOrganisation` only with an attested organisation
statement, and a Nuts token is one unless a presentation holds a credential
type the deployment declares user-authenticated (Nuts RFC021 §8). A
domestic issuer (`contact_point = false`, a required key) declares the
countries, issuing authorities and provider identifier prefixes it may
assert, and an attribute outside them, or holding a C0, C1 or bidi-control
character, or over its length cap, is refused naming the field. A
professional below level substantial, or below level high from 26 March
2032 (2026/2099 Art. 6(3)), is refused. The `sub` is recorded with its
issuer (`External::remote_subject`) and never bound to a local party, and a
`federation` issuer contributes no role. The field `consent.reference`
carries the reference of the consent decision the issuer rendered its
authorization on, the Consent entity of the IHE BALP 1.1.4 3:5.7.6 consent
decision record: one string, a coded value refused naming the field, read
onto the caller as `Caller::consent_reference` when the table maps it. The
field `correlation_id` carries the log correlation id of a chained
organisation request, which the requester sets and each hop carries on,
only from the source the table maps (a claim of the verified token or an
attested `authorization_details` member, never a request header): one
string, read onto the caller as `Caller::correlation_id`.

**The contact-point profile** (`federation::contact`). A
`contact_point = true` issuer is NCPeH-A's authorization server, and its
token carries what that server read from the validated HP Identity
Assertion and Treatment Relationship Confirmation, under `ehdsi`
(`mapping = "ehdsi"`; the claim names are our own design). It requires
`sender_constraint = "required"` (3.15) and fails to load without it,
naming the key, since the assertion lives up to 4 h. It declares the
participating `countries` and no provider prefixes, and configures the
country and the issuing authority, which the assertion does not carry.
The mandatory attributes are eHDSI SAML Profile 10.0.0 §2.3's, with the
§2.1 assertion window. A refusal carries its MyHealth@EU Requirements
Catalogue 10.0.0 §1.25 code name (`contact::EhdsiCode`, `Unclassified::ContactPoint`):

- no professional: `ERROR_HPI_NO_INFORMATION`;
- a missing NameID or NameID format, a format outside the three of §2.1,
  a missing name or role, `on_behalf_of` missing for role 44, or a purpose
  of use other than `TREATMENT` or `EMERGENCY`:
  `ERROR_HPI_INSUFFICIENT_INFORMATION`, with the missing fields (the
  format outside the three and the purpose are our own design, as §1.25 has
  no code for them);
- no `organization-id`: `ERROR_HPI_HAI_NO_INFORMATION`;
- no point of care, facility type or `homeCommunityId`:
  `ERROR_HPI_POC_NO_INFORMATION`;
- an authentication class outside the seven of §2.1:
  `ERROR_HPI_AUTHENTICATION_NOT_RECEIVED` (requirement 01.01);
- a missing assertion attribute, or a token that outlives the IdA (4 h) or
  the TRC (2 h) window, with 60 s of drift:
  `ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED` (requirement 11.01.02).

A discovery-phase token carries no TRC field and no `patient.id`: the TRC
is issued once the patient is identified (eHDSI SAML Profile 10.0.0 §4),
so the professional's patient identification presents the IdA alone. It is
admitted, held to the IdA window, and `External::trc_patient` reads no
patient from it, so a product refuses every patient-data request under it
(FerroFED and FerroEHR answer `trc-missing`). A token that carries any TRC
field or a `patient.id` carries `trc.id` and both TRC window bounds, or is
refused `ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED` naming the missing ones
(FerroHEALTH/FerroAUTH#314).

`EhdsiCode::of` names any other invalid token, and an unreadable key set or
upstream, `ERROR_SEC_GENERIC` (requirement 11): §1.25 has no code for an
unreadable key set, and its `ERROR_REGISTRY_NOT_AVAILABLE` belongs to
requirement 05, the Patient Summary. Nothing is refused on
the description of the HP, the role or the point of care (requirements 01
and 01.02), and no level is judged (Interoperability Specifications 8.0.1
§2.4.3): the class is recorded as received. A contact point never admits
an organisation. Whether a request is a patient-data request, which needs
`patient.id`, is the product's to check.

The IdA's `NameID` is `professional.hp_identifier` and its `@Format` is
`assertion.name_id_format` (one string, a coded value refused naming the
field), each `@Format` one of the three URNs of eHDSI SAML Profile 10.0.0
§2.1. Both are mandatory there, and one string under two formats names two
identifiers, so a product reads them as one pair, `Caller::name_id`, a
`contact::NameId` with its `contact::NameIdFormat`, beside
`assertion.issuer` (FerroHEALTH/FerroAUTH#291).

The contact point may relay the UUID of the cross-border request message,
the WS-Addressing `MessageID` of the request (eHDSI NCPeH Components
Specifications 10.0.0 §3.5), as the field `message_id`, read by the `ehdsi`
mapping from `ehdsi.message_id`. It is optional: a token without it is
admitted. It is one string held to the bounds of every field (no control or
bidirectional control character, at most 256 characters), a `urn:uuid:`
form taken as relayed, and a product reads it as `Caller::message_id`, a
`federation::MessageId` whose `Debug` rendering never carries the value, to
join its access record to the contact point's audit entry
(FerroHEALTH/FerroAUTH#432).

**The `nl` profile** (`profile = "nl"`, `profiles/nl.toml`). The harmonised
BgZ and eOverdracht authentication of the openEHR Federation Tier
specification 1.0.1 Annex B §B.4a: a requesting care provider signs its own
client-credentials access token (§B.4a.2), and the healthcare attributes
travel in an `authorization_details` entry of type `nl-gis-v1` (§B.4a.3).
A preset file may carry a `federation` table (`Preset::federation`), which
the issuer's own `[[auth.federation]]` table is set over
(`FederationSection::over`) and which an issuer of another kind refuses.
The `nl` table declares the issuer domestic in `NL`, with the CIBG as the
issuing authority (§B.3), the URA prefix `urn:oid:2.16.528.1.1007.3.3.`
(the §B.4a.3 example), the attested entry of type `nl-gis-v1` as the
organisation's access statement (§B.4a.1 verifies only the organisation),
`purpose_of_use` and `nl.organisation_type` read from the entry, and
`required_fields` (`purpose_of_use`, `nl.organisation_type`, `nl.ura`): a
federated query is the query use case, for which "Organization type must
travel" (§B.4a.4), and a token missing one is refused as
`Unclassified::RequiredFields`. The URA is the signing organisation's own,
so the deployment configures it as a constant. `requires_sender_constraint`
holds the issuer to `sender_constraint = "required"` (§B.4a.2, FAPI 2.0's
sender-constrained tokens), and with no `typ` in §B.4a.2 the issuer fails
to load until it sets `token_types`. The §B.4 Nuts Generic Functions track
is not this profile: Annex B calls the two "not silently mergeable".

### 3.15 Sender-constrained tokens

A token may be bound to a key its client proves with a DPoP proof
(`rfc9449`) or to the client certificate of the mutual-TLS connection
(`rfc8705 §3`). The token says so in its `cnf` claim, or in the `cnf`
member of its introspection response: `jkt`, the RFC 7638 SHA-256
thumbprint of the DPoP key (`rfc9449 §6.1`, `§6.2`), or `x5t#S256`, the
SHA-256 of the certificate's DER encoding (`rfc8705 §3.1`, `§3.2`). The
module is `sender` (FerroHEALTH/FerroAUTH#220).

**Per issuer, `sender_constraint`**, `none` (the default) or `required` on
each `[[auth.issuer]]`. Under `required` a token without `cnf` is refused.
Whatever the setting, a token that carries `cnf` is held to it on every
verifier of the crate, and the gate holds every caller a product's own
verifier returns to it too:

- a `jkt` needs a `DPoP` request whose proof's key has that thumbprint; the
  same token under the `Bearer` scheme is refused (`rfc9449 §7.2`);
- an `x5t#S256` needs the certificate it names; a token without one, or
  with another, is refused with `invalid_token` (`rfc8705 §3`);
- a `cnf` that is no object, is empty, or names any other member is
  refused, since nothing here can confirm it (our own design);
- a `DPoP` request whose token names no `jkt` is refused (`rfc9449 §7.1`).

An introspection response's `token_type` is `DPoP` exactly when it names a
`jkt` and otherwise absent or `Bearer` (`rfc9449 §6.2`), and a held
response is checked against the request's binding again on every request.

**The DPoP proof** arrives in the `DPoP` header beside `Authorization: DPoP
<token>`, and `[auth.dpop]` turns the scheme on: without the table the
scheme is not admitted. `sender::proof::ProofCheck` runs every check of
`rfc9449 §4.3`, each refusal its own `sender::Check`: one header (check 1),
a single well-formed JWT in `token68` (2), `jti`, `htm`, `htu`, `iat` and
`ath` present (3), `typ` `dpop+jwt`, compared as a media type
(`rfc7515 §4.1.9`) (4), an asymmetric algorithm of the configured list,
default the token list of 3.3 (5), the signature verified with the `jwk`
header (6), a `jwk` of type EC, RSA or OKP with no private member (7),
`htm` the request's method, case-sensitive (8), `htu` the request's URI
(9), `iat` within the window (11), and `ath` the hash of the token and the
`jkt` the token's (12). No resource-server nonce is issued (`rfc9449 §9`
makes it optional), so check 10 has nothing to compare.

**The `htu` is compared with the configured external URL**, never with the
URI the server sees: behind a TLS-terminating proxy the client addressed
the proxy (`rfc9449 §4.3` check 9, "the HTTP request in which the JWT was
received"). `[auth.dpop] external_url` is the surface's base URL as its
clients address it, and the expected `htu` is that URL with the request
path appended. Both sides are normalized first (`rfc3986 §6.2.2`,
`§6.2.3`, which `rfc9449 §4.3` has a server apply): scheme and host
lowercased, the default port dropped, dot segments resolved, an
unreserved percent-encoding decoded and every other one in upper case, the
query and fragment ignored.

**The window**: a proof is accepted for `max_age` after its `iat`,
default 60, at most 300, and an `iat` up to `clock_skew` ahead,
default 10 (`rfc9449 §11.1`, "on the order of seconds or minutes"; the
values are our own design).

**Replay.** The `jti` of every accepted proof is recorded for its window,
and a proof whose `jti` was recorded is refused (`rfc9449 §11.1`). The
record is the SHA-256 of the `jti` (`sender::replay::ProofId`), a `jti`
over 256 bytes is refused, and the record is written after every other
check, so a refused request spends nothing. The store is the product's,
`sender::replay::ReplayStore`, supplied as a product supplies a `Verifier`:
one atomic call that records a proof and answers whether it was unseen. A
store that fails answers `503` (`Rejection::Upstream`) and never admits a
proof. The crate ships `MemoryReplayStore`, whose refusal holds **within one
process only**: a replay to another replica is admitted there, the case
`rfc9449 §11.1` names ("may not always be feasible in practice, e.g., when
multiple servers behind a single endpoint have no shared state"). A product
that runs more than one replica supplies a store all of them share
(FerroFED's PostgreSQL table, FerroHEALTH/FerroFED#1637). A full in-memory
store refuses a new proof with `503` rather than forgetting one inside its
window. Only DPoP proofs are recorded, never a bearer access token, which
is presented on many requests within its life (`rfc6750 §1.2`).

**The client certificate** is the product's to read from its TLS layer
(`rfc8705 §3`), as `sender::ClientCertificate` in the request's extensions,
where the gate reads it; its trust chain is not checked (`rfc8705 §6.2`),
and behind a TLS-terminating proxy how it reaches the product is the
deployment's (`rfc8705 §6.5`). A certificate-bound token uses the `Bearer`
scheme.

**The wire.** A proof that fails is `401` with `DPoP error="invalid_dpop_proof"`,
a `DPoP` request whose token or binding fails `401` with `DPoP
error="invalid_token"` (`rfc9449 §7.1`, Figure 16), and a missing credential
is challenged with `Bearer` and `DPoP` beside each other (Figure 17). No
`error_description` is sent (3.7), and the `algs` parameter, a SHOULD, is
left out. Outside the gate, `ResourceServer::authenticate_bound`,
`Introspector::authenticate_bound` and `Verifier::verify_bound` take the
`sender::Binding` a request proves, and `ProofCheck::authenticate` runs the
whole `DPoP` request; a product verifier that does not implement
`verify_bound` refuses every `DPoP` request (`Check::Unsupported`).

**The client half.** A client grant binds the tokens it is issued, as its
`token_binding` says (FerroHEALTH/FerroAUTH#318):

- **to a DPoP key** (`client::dpop::DpopKey`, P-256 signing ES256 or P-384
  signing ES384, `rfc7518 §3.4`). Every token request carries a proof whose
  header has `typ` `dpop+jwt` and the public `jwk`, and whose claims are
  `htm`, `htu` (the URL with no query or fragment), `iat` and a fresh `jti`
  (`rfc9449 §4.2`). A request that presents the token adds `ath`, the
  base64url SHA-256 of the token, and sends `Authorization: DPoP` (`§7.1`).
  Only a token of type `DPoP` is taken (`§5`). A `400 use_dpop_nonce` from
  the token endpoint (`§8`), or a `401` whose `DPoP` challenge names
  `use_dpop_nonce` from a resource (`§9`), is answered once with a new
  proof carrying the nonce. The resend signs a new client assertion, since
  `rfc7523 §3` makes each one single-use. Nonces are kept per origin and per
  role, so an authorization server's nonce and a resource server's are never
  confused (`§9`). `DpopKey::proof` and `DpopKey::remember` are the seam a
  product's own HTTP client calls. `TokenSource::send` is the crate's own
  call path: each `Attempt` carries the `Authorization` value and that
  attempt's proof, and `TokenSource::call` refuses a DPoP-bound source
  without sending anything, since a call handed the `Authorization` value
  alone cannot prove the key;
- **to the client certificate** of its TLS identity. Every token that states
  a binding must name that certificate: a `cnf` member of the token
  response, in the form `rfc8705 §3.2` gives introspection, or the `cnf`
  claim of a JWT access token (`§3.1`). A binding to another certificate or
  another confirmation method is refused before the token is cached or used.
  An opaque token that states nothing passes as sent, since an access token
  is opaque to its client (`rfc6749 §1.4`). The thumbprint comes from the
  identity the grant presents, never from a separate setting, so the check
  can never compare against a certificate the connection does not present.

`Onward` carries both bindings, and its cache key names the key or the
certificate, so a token bound to one never serves a request proven with
another. The `[<lane>.credentials.oauth]` table takes `dpop_key_file` or
`certificate_bound`, and never both.

### 3.16 The onward grants

A product that calls another service on behalf of its caller obtains an
onward token for that service with `client::onward::exchange::Onward`,
behind the default `fetch` feature (FerroHEALTH/FerroAUTH#217). The
caller's token travels to the token endpoint only, never to the service,
as 3.5 requires.

A lane declares its onward target in `[<lane>.credentials.onward]` (4),
which `CredentialsSection::onward` resolves into the client and its
`Target`.

**The two grants**, chosen by the issuer's `onward_grant` profile key:

- `token_exchange` (`rfc8693 §2.1`), the default: the caller's token as
  `subject_token` with its `subject_token_type`, an optional `actor_token`
  (an access token of the actor's own, with `actor_token_type`, or, under
  `Onward::with_actor_assertion`, which the onward table's
  `actor_assertion = true` asks for (FerroHEALTH/FerroAUTH#340), an RFC 7523 assertion of the requesting
  client signed for each request, with the claims and `aud` of its client
  assertion, a `jti` of its own and the JWT type of `rfc8693 §3`, whose
  issued token is held to the client as its actor, FerroHEALTH/FerroAUTH#321), `scope`
  when the target names one, and the target as `resource` (`rfc8707 §2`,
  an absolute URI without a fragment) or `audience`, as `onward_indicator`
  declares. The response must name `issued_token_type`
  (`rfc8693 §2.2.1`) as an access token or a JWT.
- `jwt_bearer` (`rfc7523 §2.1`): the caller's token as `assertion` and
  `scope` naming the target, with no actor token and no `resource` or
  `audience`. A subject the classification calls `System` or
  `ExternalOrganisation` is refused before anything is sent
  (`OnwardError::UserPrincipalRequired`).

The client authenticates as its `ClientCredentials` say, `private_key_jwt`
(`rfc7523 §2.2`) the form `rfc9700 §2.5` recommends. The profile adds what
differs between authorization servers: `onward_parameters` (extra request
parameters, never one the client writes itself and never a
`requested_token_type` naming a refresh token), `onward_client_id`
(`client_id` beside a client assertion, which `rfc7523 §3` leaves
optional), `onward_subject_audience` (the subject token's `aud` must name
the requesting client before it is sent) and `onward_preview` (variants
the authorization server labels preview, refused). The `entra` preset is
the on-behalf-of flow (`jwt_bearer`, `requested_token_use = on_behalf_of`,
`client_id` sent), the `keycloak` preset the standard token exchange
(`audience`, `requested_token_type` of an access token, delegation with an
`actor_token` refused as Preview). No preset states `max_onward_lifetime`,
since no vendored document does; a deployment sets it, and an issuer
without it refuses to build a client. `offline_access` is never sent.

**Fail closed.** A refused or unreadable answer is `OnwardError::Token`
with the upstream status; `interaction_required` is
`OnwardError::InteractionRequired` with the `claims` challenge the body
carries, which the product answers with its own `401`; a response carrying
a refresh token is refused. The client never falls back to its own
credentials, and a caller with no verified token (a Basic caller, or one an
edge asserts with no issuer and no claims) is refused before anything is
sent. `rfc6749 §5.2` does not list `interaction_required` for the token
endpoint; the mapping follows the on-behalf-of error example.

**The onward check**, run on the token as issued and again on every cache
hit. The token is decoded, not verified: it came from the token endpoint
over the connection the client opened. It is refused unless:

- its `iss` is the issuer asked;
- its `aud` is present and every value lies in the target's audiences,
  configured on the `Target` and never derived from a scope;
- its `iat` and `exp` are present, `exp` is no later than `iat` plus
  `max_onward_lifetime`, and neither it nor the subject token has expired;
- for a MyHealth@EU contact-point caller, its `exp` is no later than the
  caller's `assertion.not_on_or_after` or `trc.not_on_or_after`, each when
  carried, plus 60 s of drift (eHDSI SAML Profile 10.0.0 §2.1, §4.1),
  refused as `Rejected::AssertionWindow` naming the window; an unreadable
  end is refused (our own design, FerroHEALTH/FerroAUTH#295);
- it carries every claim and value of the profile's `expect`;
- it names the requesting client as its actor: `act` (`rfc8693 §4.1`,
  `iss` and `sub`) equal to the actor token's actor, or to the issuer and
  the client id when none was sent, or, with no `act` and no actor token,
  the first of the profile's `client_claims`;
- on a `persons` issuer (a delegated exchange), every claim of
  `person_equality` is equal in the subject and the issued token (`iss`
  and `sub` by default, `oid` and `tid` under `entra`);
- on a `patients` issuer, every claim of `person_equality` is equal as on
  a `persons` issuer, the token reads as a patient token of that issuer
  (3.14: the `patient` context alone), and every claim of the subject
  token's patient context is equal in the issued token: `patient`, `ehrId`
  and the deployment's `PatientClaim` (3.13), each when the subject token
  carries it;
- on a `federation` issuer, the subject token's issuer is in its
  `[[auth.federation]]` table's `exchanges_from`, the token reads under
  that table as 3.14 reads a federation token, a professional's
  `professional.hp_identifier` equals the subject claim `person_mapping`
  names, a person's exchange never yields an organisation's token, the
  subject's consent decision reference (3.14), when it carries one, is
  carried over with the same value (`Rejected::Consent`), so is its
  correlation id (`Rejected::Correlation`), and on a chained route
  (`Target::with_correlation_claim`) the correlation claim is carried over.
  A chained route refuses a subject token without that claim before
  anything is sent (`OnwardError::NoCorrelation`).

Only a `persons`, a `patients` or a `federation` issuer issues onward
tokens. A `patients` issuer, a deployment's separate patients realm or
tenant, exchanges a patient's own token alone: before anything is sent it
refuses a caller that is not `CallerKind::Patient`
(`OnwardError::PatientRequired`) and a patient whose token names no
patient context (`OnwardError::NoPatientContext`). No specification
governs the patients route: our own design over `rfc8693 §2.1` and
`rfc7523 §2.1`.

**The cache** is keyed by a SHA-256 over the issuer, the grant, the hash of
the subject token and of the actor token, the target's audiences and
indicators, the scope and the profile's extra parameters, so one subject
token sent to two targets is two exchanges and a token issued for one
target never reaches another (`rfc8707 §2`). An entry lives until
`refresh_margin` (capped at half the time left) before the earliest of the
issued token's `exp`, the subject token's `exp` and `expires_in`, and holds
at most 4096 entries. No token reaches a log line or a `Debug` rendering.

The check, the cache and the profile keys are our own design over
`rfc8693`, `rfc7523` and `rfc8707`.

### 3.17 The party binding

Every product attributes a request to the token's issuer and subject, and
FerroEHR binds every request of a professional or a representative to their
own demographic `PERSON`. The rules of that lookup live in `party`, beside
the classification (3.14), and each product supplies only its store, a
`party::source::PartySource` it implements over an indexed table of its
own. The library never issues a token and never provisions a party. No
specification governs resolving a login to a party: our own design, over
the sources cited here.

**Who is looked up.** A `Person`, `Delegated` or `Representative` caller of
a `persons` issuer that has an `[[auth.party]]` table, and a Basic user,
whose credential is always a person's (3.14). A representative is looked
up by their own login, never by the subject they represent. `Patient`,
`System`, `ExternalPerson` and `ExternalOrganisation` callers are never
looked up: a `federation` token's `sub` names a user in another issuer's
namespace (`rfc7519 §4.1.2`, "locally unique in the context of the
issuer"). A guest is looked up only when its table sets `guests = true`, and
binds with the guest mark. A caller of a `persons` issuer with no table is
`Unbound`.

**The match.** The value of the issuer profile's `person_key` (`oid` under
`entra`), which the classification and `person_equality` read too, is put
in the canonical form the table's `identifier_type` declares (`guid` and
`uuid` in lower case, any other type exactly) and handed to the source with
the table's `identifier_issuer`, which compares it exactly. A Basic user is
looked up by the key the product maps it to
(`PartyBinding::with_basic_user`), and `PartyBinding::check_basic` refuses a
store with an unmapped user. The source reports every party carrying the
value (with its state, its `professional` and `representative` markers, its
memberships and its representation relationships) or the tombstone of a
deleted one, and never chooses between two.

**The outcomes.** `party::Outcome`, left on the caller (`Caller::party`):

- `Party`: one party, with the marker the caller's kind needs (`professional`
  for `Person` and `Delegated`, `representative` for `Representative`; a
  party with both binds either), the identifier that matched, the groups the
  token names that the party belongs to, its representation relationships
  (whether one covers the request is the product's check), and whether its
  record is incomplete (`provisional`) or its caller a guest;
- `WrongMarker`: one party without the marker, with its reference;
- `Unbound`, `Ambiguous` (two or more parties, never resolved to either),
  `Deprovisioned` (the tombstone);
- `Inactive` and `Abandoned`: the state the product reports (openEHR
  `800|inactive|` and `801|abandoned|`, `rm-common master06` §Abandoned
  and Inactive States), with the reference;
- `KeyClaimMissing`: the token lacks its `person_key` claim (claims "are
  present only if a value exists", Microsoft, "Access token claims
  reference"), or a Basic user maps to no key;
- `GroupsUnavailable`: a groups overage marker in place of the group claim
  (`_claim_names` naming it, or `hasgroups = true`, the "Groups overage
  claim" of the same reference) with no adapter, an adapter failure carrying
  the upstream status and `Retry-After`, or a group claim that is no array
  of strings. Where the profile names an adapter, the adapter registered
  under that name (`PartyBinding::with_adapter`) is called before the
  outcome is decided, and its groups stand in for the claim. An absent group
  claim is the empty set.

The groups are the source's memberships intersected with the token's group
claim on each request, so a person in two groups has two. A source that
fails is a `party::source::SourceError`, never `Unbound`; behind the guard
(`Gate::with_party`) it answers `503`, and every other outcome reaches the
handler, which decides what it means. The library calls the source once
per request and holds no cache, no expiry and no invalidation hook (owner
ruling 2026-11-05): a source meets its product's latency budget by indexed
reads, and a cache is proposed only with measurements and an owner ruling.

**The `idp-entra` adapter.** Behind the `idp-entra` feature,
`idp::entra::GraphAdapter` resolves an Entra ID groups overage. Above its
limit ("150 for SAML tokens, 200 for JWT tokens") Entra ID leaves `groups`
out and carries `_claim_names` and `_claim_sources`, or `hasgroups`, in its
place; the `_claim_sources` URL is "an Azure AD Graph URL", and a service
should "use the `idtyp` optional claim ... to construct a Microsoft Graph
URL" (Microsoft, "Access token claims reference", §Groups overage claim).
The adapter never reads `_claim_sources`: it builds
`{base_url}/users/{oid}/getMemberObjects` for a user token and
`{base_url}/servicePrincipals/{oid}/getMemberObjects` for one whose `idtyp`
is `app` (Microsoft, "Optional claims reference"), from the configured
Graph root and the token's `oid`, which must be a GUID, and refuses any
other `idtyp` with `AdapterError::Claim` before it calls anything. It sends
the `POST` of the Microsoft Graph v1.0 reference `directoryObject:
getMemberObjects` with `securityEnabledOnly` as configured, under a
client-credentials token of `client::cache::TokenSource` renewed once on a
`401`, and reads only a `200 OK` "String collection" (the pages are pinned
cache only, `docs/specs/microsoft-graph/PROVENANCE.md`). A deployment
turns it on per issuer with `adapter = "idp-entra"` on an `entra` issuer,
builds the adapter from a `GraphSection` (the Graph root, `timeout`,
`max_response_size`, `security_enabled_only` and the `credentials` of the
Graph token) and registers it under `idp::entra::NAME`. The `entra` preset
names no adapter, so a build without the feature loads every `entra`
issuer that does not ask for one.

Every failure is `GroupsUnavailable(GroupsCause::Adapter(..))`, never an
empty set: a status other than `200` is `AdapterError::Status`, with the
`Retry-After` seconds of a throttled `429` ("Microsoft Graph throttling
guidance"); a call past the budget is `AdapterError::Timeout`; a Graph
token that cannot be obtained, or an answer past `max_response_size`, that
repeats a member name, is no collection of strings or names a next page, is
`AdapterError::Unreadable` with the cause. A product answers these as an
upstream failure (`503`) and `GroupsCause::Overage` as a refusal. The call
has its own budget, `timeout` (`2s` by default), over the token fetch and
the Graph round trip together, and answers one request: nothing is cached.
Its latency is outside a product's lookup budget (FerroEHR's 2 ms at p99
excludes it). Every request of a user above the overage limit costs one
Graph round trip and draws on the application's Graph throttling
allowance. The perf case measured a p99 of 55.8 ms over 100 overage
requests against a stub Graph with 50 ms injected latency (2026-11-05),
beside the 2 ms lookup budget, and fails when the p99 passes the adapter's
timeout. A bounded cache needs measurements and an owner ruling. The bounds
are our own design.

**The configuration.** One `[[auth.party]]` table per bound `persons`
issuer, with `deny_unknown_fields`, checked when the section resolves:

```toml
[[auth.party]]
issuer = "https://login.example.org/tenant/v2.0"   # a trusted persons issuer
identifier_issuer = "urn:example:ferroehr:login"   # never shared by two tables
identifier_type = "guid"                           # declares the canonical form
group_claim = "groups"                             # empty: no group is read
group_identifier_issuer = "urn:example:ferroehr:groups"   # set with group_claim
guests = false                                     # whether a guest is looked up
```

A table has no `claim` key: the issuer profile's `person_key` names the
key claim, and `claim` is refused as an unknown key. A table naming no
trusted `persons` issuer, two tables naming one issuer or sharing an
`identifier_issuer` (two subject spaces would merge, naming both), a
`group_claim` without its `group_identifier_issuer`, and a `person_key` on
the banned list of 3.14 (`oidc-core §5.7`) fail too, as
`ConfigError::Party`. `PartyBinding::with_resolved` builds the binding from
`Resolved`. The audit line records the outcome and the party reference
(3.6), and no `Debug` rendering carries the key value, a group or a
represented subject.

### 3.18 The eHDSI assertion check

`federation::assertion`, behind `ehdsi-assertion`, is the check an
authorization server acting for NCPeH-A runs on the HP Identity Assertion
and the Treatment Relationship Confirmation before it issues the
contact-point token of 3.14 (FerroHEALTH/FerroAUTH#294). The library still
issues nothing: it reads two signed SAML 2.0 assertions and returns typed
values, and `identity::ehdsi_claim` writes them as the `ehdsi` claim the
contact-point profile reads.

- **The signature.** The assertion is the document element, signed by an
  enveloped `ds:Signature` (eHDSI Cryptographic Algorithms 9.0.0 §4.1;
  SAML Profile 10.0.0 §2.2, §4.2). One shape is accepted, which is what
  rules out signature wrapping: one `ds:Signature` in the document, a child
  of the document element; no nested `saml:Assertion`; one `ds:Reference`
  whose URI names the document element's `ID`, carried by no other
  attribute named `ID`, `Id` or `id`; the enveloped transform then
  exclusive canonicalization; `KeyInfo` naming the signer by its
  certificate or its subject key identifier. Every value is read from that
  element by child path, never by ID lookup. Exclusive canonicalization
  (W3C Exc-C14N 1.0) is our own implementation over `roxmltree`, which
  refuses a DTD, under a 64 KiB and 4096-node cap (our own design). A
  linear pre-scan holds the element depth to 32 and the namespace
  declarations to 128 before `roxmltree` parses (our own design), since its
  namespace copies cost time quadratic in nested declarations, and the
  canonicalization keeps one rendered-namespace map with an undo log
  (FerroHEALTH/FerroAUTH#315). The line ends are translated before parsing
  (XML 1.0 §2.11), since `roxmltree` 0.21 leaves a carriage return before a
  reference untranslated (FerroHEALTH/FerroAUTH#316).
- **The floor.** SOG-IS ACM 1.3 at "Legacy valid beyond 2025"
  (Cryptographic Algorithms 9.0.0 §2): an RSA modulus of at least 3000 bits
  (§4.1, Note 27), PKCS#1 v1.5 or PSS with SHA-256, SHA-384 or SHA-512
  (§5.2). SHA-1 and SHA-224 are refused as `Floor::Hash`, an ECDSA method
  or key as `Floor::EllipticCurve` ("if agreed by all countries").
- **The signer.** A `TrustedSigner` pairs the `saml:Issuer` URI with the
  seal certificate the SMP publishes for it (SMP Profile 10.0.0 §3.1.3,
  §3.1.6). It is refused at registration below the floor, on an elliptic
  curve, or outside the X.509 Certificates Profile 7.0.0 §3.1 seal profile
  (`KeyUsage` critical with `digitalSignature` and `keyEncipherment` alone,
  no `ExtendedKeyUsage`, `BasicConstraints` naming no CA, a
  `SubjectKeyIdentifier`); its validity is checked at each assertion
  (§2.4). Revocation is the deployment's: it removes a revoked
  certificate from the set (our own design).
- **The assertion.** `@Version` 2.0; `@ID` a UUID, as `urn:uuid:` (SAML
  Profile 10.0.0 §2.1) or behind the `_` that makes it an `xs:ID` (SAML 2.0
  Core §2.3.3), since the profile's URN is no `NCName`; `IssueInstant`,
  `NotBefore`, `NotOnOrAfter` and `AuthnInstant` in UTC; a window of at most
  4 h (IdA) or 2 h (TRC), with 60 s of drift at each boundary; an `Audience`
  the validator accepts; `sender-vouches`; and for the IdA no
  `SubjectConfirmationData` (§2.1).
- **The attributes.** The IdA's in the order of 3.14, so an assertion and
  its token are refused with the same §1.25 code; the `Role` and
  `PurposeOfUse` values are the HL7 v3 elements §2.3 requires. The TRC
  carries `PreviousSession`, names the IdA in `Advice/AssertionIDRef` with
  the same `NameID` and format (§4.1; Messaging Profile 10.0.0 §5.5.1), and
  its patient `subject-id`, whose absence answers
  `ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED` (the owner's decision on
  FerroHEALTH/FerroFED#1620); the §4.4 EUDI Wallet attributes are held to
  their pairing.

- **The instants.** `IssueInstant` no more than 60 s ahead and before
  `NotOnOrAfter` (SAML 2.0 Core §2.3.3), `AuthnInstant` no more than 60 s
  after the `IssueInstant` or now (§2.7.2), and `SessionNotOnOrAfter`, when
  present, no more than 60 s behind (§2.7.2; SAML Profile 10.0.0 §2.1,
  §4.1). The session end is returned, and `Exchange::ends` is the earliest
  window or session end, the latest `exp` a token issued on it may carry.
- **The exchange and its replay.** `Validator::exchange` checks the IdA
  alone (the discovery phase) or the IdA with one TRC, and admits that
  exchange once: the `ReplayGuard` `Validator::new` requires records it,
  keyed by the issuer and `ID` of each assertion, until the earliest end
  plus the drift (RFC 7522 §3, item 6). The key is the exchange, not the
  IdA alone, since the IdA "always takes the role of a Supporting Token"
  (Messaging Profile 10.0.0 §5.5.1) and comes again with each TRC of its
  session (SAML Profile 10.0.0 §6, non-normative). The crate ships a
  `MemoryReplayGuard` for one process; a product on several replicas
  supplies a shared store. A guard that cannot answer admits nothing
  (`ERROR_SEC_GENERIC`).
- **The caller's obligation.** Sender-vouches names no presenter, so the
  caller authenticates the presenting party as acting for the issuer:
  NCPeH-A verifies NCP-B's message signature over the Body and the
  assertions (Messaging Profile 10.0.0 §5.5.2), and an authorization
  server acting for NCPeH-A authenticates its national connector, for
  instance by its client certificate (RFC 8705 §2).
- **Interoperability.** An `InclusiveNamespaces PrefixList` naming a
  prefix outside SAML Profile 10.0.0 §1.4.2 is refused as
  `Integrity::Canonicalization` (Cryptographic Algorithms 9.0.0 §4.1:
  "other prefixes than the ones defined in [SAML Profile] MUST NOT be
  used"). Signers built on OpenSAML often list `xs`, so their assertions
  are refused until the issuer fixes its signer.

Every refusal is an `AssertionError`, whose `code()` is its §1.25 code
name: each `Integrity` refusal answers
`ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED`, the attribute refusals the codes of
3.14.

## 4. The configuration model

Every product embeds the same `[auth]` section, deserialized with
`deny_unknown_fields`, with every default inline in the section's `Default`
impl, and every secret with a `_file` sibling of which exactly one is set.
Environment overrides use the product's own prefix and the family's
double-underscore path (`FERROBRIDGE__AUTH__ISSUER`, `FERROEHR__AUTH__…`),
applied by the product's loader over the library's section types. No
specification governs this: our own design.

```toml
[auth]
enabled = true                       # a product may refuse `false`
realm = "ferrobridge"                # the product's default
capabilities = []                    # SMART capabilities the discovery document adds
scopes_supported = []                # the scopes the product honours, listed in the discovery document
# described_issuer = "https://as.example.org/realms/ferro"  # the issuer the discovery document describes; unset for the one eligible issuer (3.8)
product_scope = ""                   # the product's own scope: `__name` or a full URI
scopeless_subjects = [               # app-only subjects granted system-wide access without a scope (3.4)
  { issuer = "https://as.example.org/realms/ferro", sub = "batch-client" },
]

[[auth.issuer]]                      # one table per issuer; none with Basic users: a Basic-only surface
issuer = "https://as.example.org/realms/ferro"
kind = "persons"                     # required: persons, patients, machines or federation (3.14)
profile = "rfc9068"                  # or "entra", "keycloak", "okta", "nl"; any profile key below overrides it
audience = ["https://bridge.example.org/fhir"]   # at least one; `aud` must contain one
algorithms = ["RS256", "RS384", "PS256", "PS384", "ES256", "ES384"]
clock_skew = "60s"                   # at most 300s
jwks_max_age = "10min"
jwks_refresh_interval = "60s"
jwks_file = ""                       # a key set handed over out of band, instead of jwks_uri
timeout = "10s"                      # one call to the authorization server
role_claims = ["roles", "groups", "entitlements"]   # this issuer's role paths (3.11); none on federation
first_party_clients = ["ferrobridge-console"]       # the clients a person signs in through (3.14)
delegates = [{ client = "partner-app" }, { sub = "actor-service" }]
mode = "jwt"                         # or "introspection" (3.10), with the table below
sender_constraint = "none"           # or "required": a DPoP- or certificate-bound token alone (3.15)

[auth.issuer.assurance]              # the level this issuer's tokens carry (3.12)
claim = "acr"
levels = { "urn:example:acr:high" = "high" }

[auth.issuer.introspection]          # only under mode = "introspection"
endpoint = ""                        # empty: the metadata's introspection_endpoint
cache_max_age = "60s"                # "0s" caches nothing; never past the response's exp
cache_capacity = 10000

[auth.issuer.introspection.client]   # or .bearer: a grant whose token authorizes the call
client_id = "ferrobridge-rs"         # the fields of [<lane>.credentials.oauth]; the issuer stands in
client_secret_file = "/run/secrets/introspection-secret"

[auth.dpop]                          # absent: the DPoP scheme is not admitted (3.15)
external_url = "https://bridge.example.org"     # the base URL clients address; htu = this + the path
max_age = "60s"                      # a proof is accepted this long after its iat; at most 300s
clock_skew = "10s"                   # an iat this far ahead is accepted; at most 300s
algorithms = ["RS256", "RS384", "PS256", "PS384", "ES256", "ES384"]

[auth.basic]
cache_ttl = "0s"                     # how long a verified credential is kept; "0s" keeps none

[[auth.basic.users]]                 # a person's credential; absent: no Basic on this surface
user = "operator"
password_hash_file = "/run/secrets/operator.phc"   # or password_hash = "$argon2id$…"
scopes = ["user/*.rs"]
roles = ["auditor"]                  # one word each (3.11)
```

Every setting of an issuer lives on its own table: no section-level value
stands in for one an issuer leaves out, and a section-level issuer setting
is an unknown key. A named refusal of a retired key lives for the one
release that retires it (owner rule, 2026-11-09); after it the strict load
refuses the key as unknown. `Resolved` holds each JWT issuer's
`Settings`, each introspected issuer's settings, and every issuer's kind,
which `Resolved::check_role_issuers` holds a product's administrator,
emergency or identifier-reader role list to: only `persons` issuers. An
`IssuerSet` routes a token to the issuer its readable `iss` names, JWT or
introspected, and an opaque token to the one introspected issuer. The
product-specific fields of an issuer entry (FerroFED's backend clients,
patient binding, contact-point claims) stay in the product's own wrapper
around the entry.

Outgoing credentials are one shape for every lane of every product:

```toml
[cdr.credentials]                    # the lane names the table; the shape is the library's
user = "bridge"
password_file = "/run/secrets/cdr-password"

[terminology.credentials.oauth]      # or the client credentials grant
issuer = "https://as.example.org/realms/ferro"   # or token_endpoint = "https://…/token"
client_id = "ferrobridge"
client_auth = "client_secret_basic"  # client_secret_post | private_key_jwt
client_secret_file = "/run/secrets/terminology-client-secret"
# private_key_jwt instead:
# private_key_file = "/run/secrets/terminology-client.pem"
# kid = "2026-10"
# assertion_alg = "ES384"
# assertion_audience = "issuer"      # the default names the token endpoint
scope = "system/CodeSystem.rs"
refresh_margin = "30s"
# mutual TLS (RFC 8705 §2) instead, or a certificate beside another method:
# client_auth = "tls_client_auth"    # or "self_signed_tls_client_auth"
# dpop_key_file = "/run/secrets/dpop.pem"  # bind tokens to a P-256/P-384 key (RFC 9449)
# certificate_bound = true                 # or to the client certificate (RFC 8705 §3)
# security_profile = "fapi2"               # FAPI 2.0: issuer, private_key_jwt or mTLS, bound tokens
# mtls_alias_hosts = ["mtls.example.org"]  # hosts a FAPI 2.0 mTLS alias may be on
# previous_private_key_file = "/run/secrets/client-previous.pem"  # published, never signs
# previous_key_overlap = "0s"             # "0s": published while the key is set
# next_private_key_file = "/run/secrets/client-next.pem"          # published ahead of a rotation
# authorization_details = '[{"type": "nl-gis-v1"}]'               # RFC 9396, sent as written
# [terminology.credentials.oauth.tls]   # read by the product's TLS reader (ferrohealth-server TlsClient)
# client_identity_file = "/run/secrets/client.pem"   # the chain and the key in one PEM
# trust_roots_file = "/run/secrets/private-ca.pem" # roots beside the platform's
```

`user`/`password` and `oauth` are exclusive; a lane that obtains no token of
its own refuses an `oauth` table at load (FerroBRIDGE's `NoGrant` shape). The
`resource` key is the `rfc8707 §2` resource indicator and `audience` the
parameter without a specification, both sent only when set (3.5).

Every outbound TLS table of the crate (`auth.tls`, the `tls` of an `oauth`
table) is `ferrohealth_config::tls::TlsClientSection`, and the crate reads no
TLS file. A table that names material resolves through the product's
`config::TlsBuilder` (`resolve_with_tls`), which feature `server-tls`
implements as `config::ServerTls` over `ferrohealth-server`'s
`tls_client::TlsClient`, so the family has one reader of TLS material and
the table's minimum version holds; `resolve` refuses such a table
(`ConfigError::TlsNotBuilt`). Every span of time is a
`ferrohealth_config::units::Duration` (`"30s"`). No specification governs the seam: our own
design.

An outbound integration is one table, `config::endpoint::EndpointSection`:
`url`, `timeout`, `connect_timeout`, `retry` (`max_attempts`,
`initial_backoff`, `max_backoff`), `tls` and `credentials`, so an operator
writes every product's integrations with the same keys. `url` is a
`SecretUrl`, so its userinfo and query render masked, and so is every
issuer identifier a table names (`[[auth.issuer]] issuer`, the onward and
the `oauth` issuer, and the issuer `[[auth.attributes]]`, `[[auth.federation]]`,
`[[auth.party]]` and `scopeless_subjects` name), which renders masked even
before the start refuses an issuer with userinfo (RFC 3986 §3.2.1; #445,
#456). One call,
`client::outbound::OutboundClient::build`, turns the table into the HTTP
engine (its timeouts, no redirects, the TLS the product's `TlsBuilder`
builds) and the authorization (Basic, or a `TokenSource`), and
`OutboundClient::send` applies both with the retry: a call that did not
reach the integration, timed out or met a `5xx` is tried again after a wait
that doubles from `initial_backoff` up to `max_backoff`. Any other answer
is the caller's. No specification governs the retry rule: our own design.
`OutboundClient::build` builds the grant's TLS from its own `oauth.tls`
only. `OutboundClient::build_sharing_tls` is the opt-in for a grant that
presents the connection's identity: when `oauth.tls` names no material, the
grant takes the configuration built from the table's `tls`, so a
mutual-TLS `client_auth` authenticates with the certificate the connection
presents (`rfc8705 §2`) and a `certificate_bound` grant binds its tokens to
the certificate the integration checks them against (`rfc8705 §3`). An
`oauth.tls` that names material still wins, and a `certificate_bound` grant
whose certificate is not the connection's is refused at build
(`OutboundError::CertificateBinding`), since the integration would refuse
every token it is issued.

A lane that reaches its upstream on a caller's behalf declares its onward
target beside its `oauth` table, which the onward client authenticates
with (3.16):

```toml
[cdr.credentials.onward]             # resolved by CredentialsSection::onward
issuer = "https://login.microsoftonline.com/<tenant>/v2.0"   # issues the onward tokens
kind = "persons"                     # persons (a delegated exchange), patients or federation
profile = "entra"                    # the preset: rfc9068, entra, keycloak, okta, nl
# token_endpoint = "https://…/token" # empty: discovered from issuer
# client_id = "…"                    # empty: the oauth table's client id
audiences = ["<cdr app id>"]         # what an onward token's aud may name
scope = "api://<cdr app id>/.default"
# indicators = ["…"]                 # resource or audience, as the profile names
# correlation_claim = "txn"          # a chained federation route
# cache = false                      # default true; false exchanges on every call,
#                                    # for a performance self-test, never production
# actor_assertion = true             # default false; name the client the actor of
#                                    # each exchange with an assertion (rfc8693 §2.1)

[cdr.credentials.onward.keys]        # any profile key over the preset
max_onward_lifetime = "90min"        # required: no preset states one

# [cdr.credentials.onward.federation]  # a federation issuer: exchanges_from and
# [cdr.credentials.onward.assurance]   # person_mapping required, over the preset's table
```

The issuer is described in the table, never borrowed from `[[auth.issuer]]`,
because the issuer of onward tokens is not always one whose tokens the
surface admits. The table refuses the start when `issuer`, `kind` or
`audiences` is unset, beside a Basic `user`, without the lane's `oauth`
table, for a profile or federation table its issuer's rules refuse, for an
issuer the onward client refuses (`ConfigError::Onward`: another kind, no
`max_onward_lifetime`, a federation table without `exchanges_from` or
`person_mapping`), and for a target its grant cannot ask for
(`Onward::check_target`: no audience, `offline_access`, a JWT bearer target
without `scope` or with an indicator, a `resource` that is not an absolute
URI without a fragment).

Validation at load, refusing the start: an enabled section that admits no
credential (no issuer and no Basic user), the issuer URL rule of 3.1, at
least one audience, at least one algorithm and none symmetric, the skew bound, every
Basic user with a parseable Argon2id PHC string and a non-empty user-id
without a colon, every scope token inside the `rfc6749 §3.3` character set
(`scope::is_scope_token`, public so a product checks its own scopes with
the same rule), every capability as 3.8 describes, a product scope in one
of the two extension forms of `smart scopes-and-launch-context`
(Extensibility: "a full URI that you control" or "any string starting with
`__`", `scope::is_extension_scope`), and exactly one of each secret and its
`_file`. An outgoing `oauth` table is held to the same issuer URL rule at
load, and its `resource` to `rfc8707 §2` ("The URI MUST NOT include a
fragment component"), so a bad grant refuses the start rather than the
first token request. The TLS files are read and parsed at load too: a
certificate file without its key file or the reverse, a mutual-TLS method
without a certificate, and roots that hold no certificate each refuse the
start, and so does `assertion_audience = "issuer"` without `issuer`.

## 5. How a product integrates

The library offers three seams, and nothing in it names a product.

- **A tower `Layer`.** `AuthLayer::new(verifier, classifier)` wraps a router.
  The classifier is the product's: a function from the matched route
  template, the method and the path to a `Target` (whether the route is
  public, which `Requirement` it carries: a SMART permission on a resource
  type, a named scope, or nothing beyond authentication, and the `target`
  and `interaction` names for the audit line). The layer authenticates,
  checks the requirement at the type level, inserts an `Access` into the
  request's extensions, runs the inner service, and writes the audit line
  from the response. A route the classifier does not know is refused (3.7).
- **An axum extractor.** `Access` implements `FromRequestParts`; a handler
  that takes it gets the caller, and one that finds none is outside the
  layer, which is a `500`, never an open door. `Access::reach(permission,
  resource_type)` answers `Any`, `Patient(id)` or `None`; `Access::has_scope`
  answers for a product scope; `Access::claims()` hands the raw claims to a
  product rule that needs more; `Access::basic_user_in` answers whether a
  Basic caller is one of a list of user-ids (#62); and
  `Access::extension::<T>()` hands back the product's own value of type `T`,
  which the issuer's resource server (`ResourceServer::with_extension`) or
  the product's verifier (`Caller::with_extension`) attached, so a
  product's per-issuer policy travels with the verified caller and is not
  looked up again by issuer string (#61).
- **The outbound side.** `BasicSender` renders the header; `ClientCredentials`
  implements the credentials-provider trait the product's upstream client
  takes (the generated ITS-REST client's for FerroBRIDGE and FerroFED, the
  FHIR terminology client's for FerroBRIDGE and FerroEHR), with `invalidate`
  for the one renewal on a `401`.

The crate is `axum`-independent at its core (the verifier, the scopes, the
credentials, the audit record) and carries the `Layer` and the extractor
behind an `axum` feature, so a product that fronts a different server keeps
the core. The HTTP fetchers (the issuer's metadata, the key set over its
`jwks_uri`, the client credentials token client) sit behind the default
`fetch` feature; a product built without it links no HTTP client and reads
its key set from a `jwks_file`. A browser runs none of it, so for
`wasm32-unknown-unknown` the manifest leaves these dependencies out and a
build script's `resource_server` cfg leaves out every module but the SMART
on openEHR grammar (3.9); a feature would have broken every product built
with `default-features = false` (no specification governs this: our own
design).

### 5.1 What each product keeps

| Product | Moves into `ferrohealth-smart` | Stays product-specific |
|---|---|---|
| FerroBRIDGE | `src/auth/{discovery,jwks,token,scope}.rs`, the token and scope halves of `guard.rs`, the audit line, `smart.rs` (the discovery document), `src/cdr/oauth/` whole | `compartment.rs` (the patient-to-EHR mapping), the route table `CLASSIFIED`, the `OperationOutcome` bodies, the operator scope and the operations it admits, the `[auth]` loader over the shared section |
| FerroTERM | `src/smart/{discovery,jwks}.rs`, the token checks and the challenge rendering of `mod.rs`, the scope parser of `scopes.rs`, the discovery document | the write-route classification, the admin listener's requirement, the per-version audience list, the `CapabilityStatement` security block, the `OperationOutcome` bodies |
| FerroEHR | `authn/jwt.rs` (the remote key source, the claim checks), `authn/basic.rs` (Argon2id and the enumeration defence), the challenge rendering, `service/terminology/oauth2.rs` (the client credentials client) | the RBAC and ABAC gate (`authz/`, Cedar), which moves to `ferrohealth-authz` (owner decision 2026-10-25), the choice of which routes carry patient data (the assurance and professional reading itself is `assurance`, 3.12), the ATNA audit, the committer identity |
| FerroFED | `auth/keys.rs`, `auth/fetch.rs`, the RFC 9068 checks of `auth/mod.rs`, the challenge rendering of `auth/refusal.rs`, the openEHR grant rules of `auth/permission/grant.rs` (3.9) | the trust list and per-issuer policy, RFC 7662 introspection for opaque tokens, the edge mode, the IUA and contact-point claims, purpose of use, the ITS-REST operation table (the classifier, `auth/permission/table.rs`) with its demographic and backend client lists, the FAPI 2.0, mTLS, DPoP and token-exchange onward grants, the HMAC references of the security log |

FerroFED's edge-assertion verifier does not fit the library's verifiers and
plugs in beside them through the `Verifier` trait, so the layer, the
`Access` and the audit line are shared and only the way a token is checked
differs. Its introspecting verifier for a token that is not a JWS
(`rfc7662 §2.2`) can move onto the library's `Introspector` (3.10).

### 5.2 The migration path

Each product moves in one pull request per product, in this order, each
green on its own gates before the next starts:

1. **FerroBRIDGE** first: its `auth/` and `cdr/oauth/` are the closest to the
   design, so the move is a deletion plus a classifier. Its `[auth]` keys
   rename where the shared section differs (`audience` becomes a list,
   `jwks_refresh_interval_ms` becomes `jwks_refresh_interval_seconds`,
   `jwks_max_age_seconds` appears), with the old keys refused by
   `deny_unknown_fields` and named in the changelog.
2. **FerroTERM**: the environment variables `FERROTERM_OIDC_ISSUER`,
   `FERROTERM_OIDC_AUDIENCE` and `FERROTERM_OIDC_ADMIN_SCOPE` become the
   `[auth]` section (or its environment form); `audience` becomes required,
   which is a breaking change for a deployment that set none; the
   `error_description` on a refusal disappears; the `typ` of `JWT` is
   accepted when the issuer's profile lists it in `token_types`.
3. **FerroEHR**: the `hmac_secret` key source is removed (section 3.3,
   algorithm), `jwks_json` becomes `jwks_file`, `allow_insecure_issuer`
   becomes the loopback rule, `audiences` keeps its list shape, `basic.users`
   gains `scopes` and keeps `roles` for the RBAC gate. The RBAC and ABAC
   gate runs on the `Access` the layer leaves, reading the roles from the
   claims as it does today, and then moves with its Cedar policy to
   `ferrohealth-authz` (owner decision 2026-10-25).
4. **FerroFED** last: its trust list wraps the library's issuer entries, its
   introspecting and edge verifiers implement the `Verifier` trait, its
   permission table stays, and its onward grants keep their own engine; the
   library's `ClientCredentials` replaces only the plain client-credentials
   case.

Each move keeps every existing test and adds none that weakens one: the
status tables and the challenge strings the products pin today are the
contract the library must meet, and a difference between a product's pinned
behaviour and this design is settled on the tracker before the move, never
by editing the test.

## 6. What `ferrohealth-smart` deliberately does not do

- **Issue tokens.** That is the authorization server (`rfc6749 §1.1`), and
  the family takes one off the shelf per deployment. A token-issuing library
  would hold a signing key in every product, which is the one key whose
  leak forges every caller.
- **Log a user in, show a consent screen, or hold an app registry.** All
  three are the authorization server's (SMART App Launch's authorize
  endpoint and registration, `smart app-launch`), and each is a product in
  itself with its own threat surface.
- **Introspect by default.** RFC 7662 trades a signature check for a network
  call per request, so a resource server that introspects by default
  inherits the authorization server's availability and latency on every
  request, and SMART only has an EHR "SHOULD support" the endpoint (`smart
  token-introspection`). Self-contained RFC 9068 tokens checked against a
  cached key set are the default; introspection (3.10) is a deployment's
  opt-in, `mode = "introspection"`, for opaque tokens from an issuer that
  mints no JWS, with a bounded cache in front of the endpoint.
- **Evaluate an authorization policy.** Roles, attributes, purpose of use
  and consent are "a lower-level responsibility in the access control
  stack" the scopes do not model (`smart scopes-and-launch-context`, SMART's
  scopes are used to delegate access), so `ferrohealth-smart` hands the
  verified `Access` on and decides nothing more. The policy decision (RBAC
  and ABAC, Cedar, a remote PDP) belongs to `ferrohealth-authz`, the second
  crate of this repository, and FerroEHR's `authz/` moves there (owner
  decision 2026-10-25).
- **Read a token from a query string or a form body** (3.3).

## 7. Reference: what the products run today and the design changes

The product code was read on `main` on 2026-10-19. The design keeps what the
four agree on and settles each difference:

| Behaviour | FerroBRIDGE | FerroTERM | FerroEHR | FerroFED | Design |
|---|---|---|---|---|---|
| Metadata location | RFC 8414, then OIDC | OIDC only | OIDC (`openidconnect`) | key set URL or file, introspection | RFC 8414, then OIDC (3.1) |
| Algorithms | RS256, ES256 (configurable, no HMAC) | nine asymmetric, fixed | configurable, HMAC allowed | ES256, ES384, PS256, RS256, fixed | asymmetric only, configurable, default six (3.3) |
| `typ` | `at+jwt` under `rfc9068`, any under `jwt` | `at+jwt` or `JWT`, absent allowed | `at+jwt` when `require_at_jwt` | `at+jwt` | `at+jwt` by default; `jwt` profile by configuration (3.3) |
| `aud` | one configured, required | version bases, optional | list, required | one, required | list, required (3.3) |
| Unknown `kid` | one refetch per interval | one refetch per cooldown | TTL cache | one refetch per interval, max age | both bounds (3.2) |
| No `kid` | single key of the family | single usable key | single usable key | single usable key | single candidate, else refuse (3.2) |
| Refusal reason on the wire | no | `error_description` | one challenge, a body per cause | a stable code per cause in the body | never (3.7) |
| `403` names the scope | no | `scope=` when one | no | no | never (3.7) |
| Key set unreadable | `503` | `401` | `503` | `503` | `503` (3.2) |
| Basic | no | no | Argon2id, decoy | no | Argon2id, decoy, scopes (3.5) |
| Client credentials out | Basic or post, cache, one renewal | none | the `oauth2` crate, cache | FAPI 2.0 engine | Basic, post, `private_key_jwt`, cache, one renewal (3.5) |

## 8. The threat model, in brief

- **Key rotation.** A new key appears in the issuer's set before it signs;
  the unknown-`kid` refetch picks it up within one request, bounded by the
  refresh interval; a withdrawn key stops verifying within the max age. A
  flood of unknown `kid`s costs one read per interval. A failed read admits
  nothing and refuses nothing as invalid (3.2).
- **Algorithm confusion.** `none` is refused outright, every HMAC algorithm
  is refused outright, and a key verifies only the algorithm it belongs to,
  so a public key from the issuer's set can never become the secret of a
  symmetric signature (`rfc8725 §2.1`, `§3.1`, `§3.2`; `rfc9068 §4`).
- **Token substitution.** `typ` must be `at+jwt` and the audience must name
  this product, so an ID token, a client assertion or another resource
  server's token is refused twice over (`rfc8725 §3.9`, `§3.11`, `§3.12`;
  `rfc9068 §4`; `rfc9700 §4.10.2`).
- **Token replay.** A bearer token is a bearer token (`rfc6750 §5.1`): the
  library bounds the damage with the audience check, a short `exp` the
  issuer sets (SMART Backend Services asks for five minutes), TLS on every
  hop, and the rule that a caller's token is never forwarded. `jti` is not
  tracked: a replay inside the lifetime at the same resource server is
  indistinguishable from the client's own retry, and the countermeasure RFC
  9700 §4.9.3 names is sender-constraining, which an issuer turns on with
  `sender_constraint = "required"` (3.15). A DPoP proof is single-use within
  its window, across replicas only when the product supplies a shared
  replay store.
- **Clock skew.** `exp` and `nbf` take the configured leeway, at most five
  minutes; a token issued in the future beyond the leeway is refused; the
  skew never widens by configuration beyond the bound (3.3).
- **Credential leakage through the product.** The audit line carries no
  token, no secret and no claim beyond three; every credential type redacts
  its `Debug`; a refusal names no claim and no scope; a token is read from
  the header only (3.3, 3.6, 3.7; `rfc9700 §4.9.3`).
- **The reverse proxy.** A deployment that terminates TLS in front of a
  product must sanitize inbound headers and protect the link to the product
  (`rfc9700 §4.13`); the library reads no `X-Forwarded-*` header and reads
  the credential from one header, `Authorization` unless the product names
  another for its edge proxy (3.3). A product that names one owes the
  sanitizing of that header at the proxy, because whatever arrives in it is
  checked as the caller's credential.
- **The issuer itself.** The issuer is trusted entirely: a compromised
  authorization server mints valid tokens for every product that trusts it.
  That is the OAuth model, and the mitigation is operational (one issuer per
  deployment, its keys rotated, its audit read), not the library's.
- **Several issuers.** A section that trusts several issuers trusts each
  only for its own tokens: a `sub` the scopeless allowlist names and the
  claims roles are read from hold for the issuer an entry names, so one
  issuer cannot mint the subject or the role another was trusted for
  (`rfc7519 §4.1.2`; 3.4, 3.11; GHSA-pfgx-xq28-2629).

## 9. Decision register

| Decision | Ground | Owner items |
|---|---|---|
| `ferrohealth-smart` is a library, a resource server and a credential client, never an authorization server | owner decision 2026-10-19 | the repository's `README.md` still describes a SMART on openEHR server that issues tokens and launch context; it needs the new statement |
| The crate is licensed BUSL-1.1 | It is hand-written code that implements the specifications above, which is the family's rule for its own code; only generator-emitted code (`fhir-types`, `hl7v2-types` in FerroBRIDGE) is published under Apache-2.0, because it is emitted from CC0 inputs and three servers depend on it. `ferrohealth-smart` emits nothing and is consumed by the family's own products (owner decision 2026-10-19). `docs/VERSIONS.md` records the licence row and `scripts/checks/versions.sh` fails on any other claim. | none |
| Machine-to-machine traffic is the client credentials grant, beside the onward grants and federation tokens; HTTP Basic is a person's credential and carries no `system/` scope; no static bearer token and no API key | owner decision 2026-10-19; owner ruling 2026-11-05 on Basic (#215, #274) | none |
| The `private_key_jwt` key is a client credential, held under `[<lane>.credentials.oauth]`, and is the one private key the library can hold; "never holds a signing key" means never a key that signs an access token, and this key signs only the product's own client assertion (owner decision 2026-10-19) | `rfc7523 §2.2`; the assertion authenticates the client to the token endpoint and no resource server accepts it as an access token (`rfc9068 §4`, the `typ` and `aud` checks) | none |
| Asymmetric algorithms only; HMAC and `none` refused; FerroEHR's `hmac_secret` source removed | `rfc8725 §3.1`, `§3.2`; `rfc9068 §2.1`, `§4` | a FerroEHR deployment on an HMAC secret must move its authorization server to published keys before the FerroEHR migration |
| `audience` is required, as a list | `rfc9068 §4`; `rfc8725 §3.9` | a FerroTERM deployment that set no audience must set one |
| One `401` for every invalid credential, naming nothing; `403` naming no scope | `rfc6750 §3.1`; `rfc9068 §4`; the omissions are our own design | none |
| `503` when the key set cannot be read | our own design | none |
| The `patient` claim is read from the access token when present | our own design (SMART places the context in the token response and the introspection response) | none |
| Under the `rfc9068` profile only `scope` counts; under the `jwt` profile `scp` is read as a fallback when `scope` is absent, for an issuer such as Entra ID that mints the array form | `rfc9068 §2.2.3` names `scope`; `scp` is no specification's, so it is admitted only outside the profile (owner decision 2026-10-19) | none |
| Product scopes (`ferrobridge.operator`, `ferroterm/admin`) are renamed to a form SMART's Extensibility section admits, a `__` prefix or a full URI, during each product's migration | `smart scopes-and-launch-context`, Extensibility (owner decision 2026-10-19) | each product's migration names the new scope and the deployments that must update their authorization server |
| Granular scopes grant nothing without a product evaluator | the safe reading of "MAY be ignored" | none |
| An access token's `jti` is read, not tracked; DPoP-bound (`rfc9449`) and certificate-bound (`rfc8705 §3`) tokens are verified per issuer, `sender_constraint = "required"` admits a bound token alone, a `cnf` token is never a plain bearer token, the `htu` is compared with the configured external URL, and the proof `jti` is recorded in a product-supplied `ReplayStore` whose in-memory default holds per replica (3.15) | `rfc9700 §4.9.3`; `rfc9449 §4.3`, `§6`, `§7`, `§11.1`; `rfc8705 §3`; the store, the window values and the refusal of an unknown `cnf` method are our own design (FerroHEALTH/FerroAUTH#220, which replaces the owner decision of 2026-10-19 that kept both in FerroFED) | a product with more than one replica supplies a shared `ReplayStore` (FerroHEALTH/FerroFED#1637); a surface admitting `DPoP` sets `[auth.dpop] external_url` |
| `resource` is the RFC 8707 resource indicator, sent when configured; `audience` has no specification and is sent only when configured | `rfc8707 §2`; FerroBRIDGE sends both today | none |
| The `kid` of the product's own JWK is configured, or defaults to the RFC 7638 SHA-256 thumbprint | `rfc7638 §3`; the default is our own design | none |
| A caller's roles are read from the RFC 9068 §2.2.3.1 claims, or the paths a deployment names, and a Basic user's from its configuration; a route table states role requirements beside scope requirements, matched without regard to ASCII case | `rfc9068 §2.2.3.1`, `rfc7643 §2.4`, `§4.1.2`; the matching and the requirement forms are our own design (owner decision 2026-10-25: authentication and the granted subject belong in this crate) | a product that read roles itself (FerroEHR's claim paths and Basic role table) moves them to `[auth] role_claims` and `[[auth.basic.users]] roles` |
| The crate parses (with its own `openehr::smart_scopes`, which moved here from `openehr-sdt` and builds dependency-free behind `openehr-scopes`, for the browser too) and enforces the SMART on openEHR grammar beside the FHIR grammar; the product's route table declares which applies per route | owner decision 2026-10-19, the move 2026-10-27; `soe master07`, `master08`; the rules the draft leaves open are listed in 3.9 as our own design | a product that named `openehr_sdt::smart_scopes` names `ferrohealth_smart::openehr::smart_scopes` |
| SMART on openEHR is DEVELOPMENT: pinned by commit, its status checked on every vendor run, upstream read weekly, and every upstream change re-vendored and recorded here as a decision naming what changed | the draft's `manifest_vars.adoc`; no release stabilises it | none yet: the draft last changed on 2026-07-19 (amendment record 1.1.0) |
| A request is the natural person's own access only for a `Patient` caller, a `patients` issuer's token naming the record subject alone; a Basic user is never the person (3.13) | Regulation (EU) 2025/327 Art. 5, 9; `smart scopes-and-launch-context`, Patient-specific scopes leaves *who* open; SMART on openEHR `master08-scopes`; #215 replaces the two answers of #171 | a product that called `Caller::acts_for_the_person` reads `Caller::is_the_person` or `Caller::kind`, and splits patients and professionals into separate issuers |
| The `ehrId` of the launch context is read from an `ehrId` claim when the issuer carries it in the token | our own design, as `patient` in 3.3; the draft places it in the token response (`soe master07`, Context Selection) | none |
| An enabled `[auth]` with Basic users and no issuer is a Basic-only surface; an enabled section that admits no credential is refused at load | our own design, fail closed; asked by the FerroEHR migration (#43) | none |
| A blank `sub` is refused, by the token check and by the gate over every verifier | `rfc9068 §2.2`; `rfc7519 §4.1.2` (#41) | none |
| A bearer value outside `b64token` is `invalid_token`; the reason of every refusal reaches the product as a typed `Reason`, never the wire | `rfc6750 §2.1`, `§3.1`; the omission is our own design (#47) | none |
| Verified Basic credentials may be cached for a configured TTL under an HMAC of the credential | our own design, FerroEHR's (#47) | none |
| `[auth]` and `[[auth.basic.users]]` take no product extension fields; policy configuration belongs to `ferrohealth-authz`, where FerroEHR's `[authz]` moves | `deny_unknown_fields` refuses a mistyped or retired key (4); policy stays out of `ferrohealth-smart` (6) (#49, not planned; owner decision 2026-10-25 on `ferrohealth-authz`) | none |
| A plain-`http` issuer on a host that is no loopback stays refused, with no development switch; a development authorization server gets TLS | `rfc8414 §2`; `discovery §3` (orchestrator decision 2026-10-20 on the FerroEHR migration) | none |
| `ResourceServer::lazy` reads the issuer on its first token, a failed read answering `503` and not repeated inside the refresh interval; `discover` stays the eager default and both return `Send` futures | our own design, FerroFED's (#55) | none |
| A product may name the header the credential travels in, schemed or bare; the default stays `Authorization` and the rules of 3.3 hold in any header | `rfc6750 §2.1`, `§3.1`; `rfc9700 §4.13` puts the sanitizing on the proxy (#56) | a deployment that names a header sanitizes it at its proxy |
| A product verifier reports an upstream failure as `Rejection::Upstream`, answered `503` like an unreadable key set | our own design (#57) | none |
| The token client authenticates with mutual TLS (`tls_client_auth`, `self_signed_tls_client_auth`), uses the mTLS alias of a discovered token endpoint, adds configured trust roots, and takes a product `reqwest::Client` | `rfc8705 §2`, `§5` (#58); certificate-bound access tokens at the resource server stay product-specific | none |
| The assertion `aud` is the token endpoint by default and the issuer identifier when configured | SMART App Launch 2.2.0, Client Authentication: Asymmetric, fixes the token URL; `rfc7523 §3` item 3 admits the issuer (#59) | none |
| The RFC 9470 step-up challenge is a crate refusal, with `acr_values` and `max_age`, and the crate checks `acr` and `auth_time` against the product's requirement | `rfc9470 §3`, `§6`; what a resource requires is the product's (#60) | none |
| `Caller` carries a typed extension map a resource server or a product verifier fills; the configuration sections still take no product field (#49) | our own design: the verifier that routed the token already knows the issuer's policy, and the crate reads no extension (#61) | none |
| `Caller::basic_user_in` and `Requirement::basic_users` answer whether a Basic caller is one of a list | our own design (#62) | none |
| The outcome of a Basic check says whether the verified-credential cache admitted it | our own design (#63) | none |
| The metadata `issuer` is compared as exact text; a product may also hold the configured issuer to its canonical URL form | `rfc8414 §3.3`, `§4`; the canonical form is our own design (#67) | none |
| A metadata document whose objects repeat a member name is refused | `rfc8259 §4` leaves the meaning to each parser; the refusal is our own design (#69) | none |
| A product may refuse metadata whose endpoints are off the issuer's origin; the check is opt-in | `rfc6454 §4`, `§5` define the origin; RFC 8414 places no endpoint, so the policy is our own design (#68) | none |
| Token introspection is a deployment's opt-in (`mode = "introspection"`), under client authentication or a grant's bearer token, with `scope`, `client_id` and `exp` required, `iss` and `aud` checked when present, and a response without `sub` read as the client's | `rfc7662 §2.1`, `§2.2`, `§4`; `smart token-introspection`; `rfc9068 §2.2` | none |
| A `scopeless_subjects` entry is `{ issuer, sub }` and admits a `System` caller of that issuer alone; `role_claims` sit on each issuer table; the string forms, bare or `<issuer>#<value>`, are refused at load | `rfc7519 §4.1.2` (a `sub` is unique within its issuer); our own design (#215, after GHSA-pfgx-xq28-2629) | a deployment rewrites each entry as a table and moves `role_claims` onto its issuer tables |
| Every issuer declares its `kind` and a profile (a preset with keys over it), every issuer setting lives on its table, and a valid token is classified as `Patient`, `System`, `Delegated`, `Representative`, `Person` or `Guest`, or refused as `Rejection::Unclassified`; a Basic credential is always a `Person` (3.14) | `rfc9068 §2.2`, `§4`, `§5`; `rfc8693 §4.1`; `oidc-core §5.7`; the vendor documents each preset cites; the classification is our own design (#215, owner ruling 2026-11-05 on Basic) | a deployment writes `[[auth.issuer]]` tables with `kind`, lists its `first_party_clients`, and drops `token_profile`, `acting_for_claim` and `client_tokens` |
| A `persons` login is resolved to its party through a `PartySource` the product supplies, once per request with no cache, keyed by the issuer profile's `person_key` in the canonical form of its `identifier_type`, against the identifiers of one `[[auth.party]]` table's `identifier_issuer`; two matches are `Ambiguous`, a source failure is an error and never `Unbound`, and the outcome is the product's to answer (3.17) | `oidc-core §5.7`; `rfc7519 §4.1.2`; Microsoft, "Access token claims reference" (the overage markers); the binding is our own design (#216, owner ruling 2026-11-05 on the cache) | a product binds its `persons` issuers with `[[auth.party]]` tables, implements `PartySource`, maps each Basic user to a key, and answers each outcome |
| A `persons` issuer's `[[auth.attributes]]` table reads the IHE IUA professional attributes and purposes of use, from claims or constants and, with `authorization_details_purposes`, the `system\|code` of each `authorization_details` entry, onto every non-`System` caller as `Caller::attributes`, and the purposes of use alone onto a `System` caller and every caller of a `patients` or `machines` issuer's table; a claim of the wrong shape refuses the token, and a coding with an empty code names none (3.14) | IHE IUA §3.71.4.2.2.1.1; `rfc9396 §2`; FHIR R4 datatypes.html; our own design over them (#376, #438) | a product reads the professional, the organisation and the purposes from `Caller::attributes` and drops its own IUA claim parser |
| A `patients` token that carries `act` is the patient's representative under `act_represents_patient`, with the top-level actor only, and is refused without it (3.14) | `rfc8693 §4.1`; Regulation (EU) 2025/327 Art 4(2); our own design (#377) | a product that records a patient's representative sets `act_represents_patient` and reads `CallerKind::PatientRepresentative` |
| The discovery document describes the issuer `[auth] described_issuer` names, which must be eligible, else the one eligible issuer; eligible is every issuer that is not `machines` and whose metadata is available; several eligible issuers without a name, or none, are refused; the table order never decides (3.8) | `smart conformance`, Metadata (`authorization_endpoint` is where a user launch starts); the choice among several is our own design, settled in FerroEHR (FerroHEALTH/FerroEHR#5426) and moved here (#469) | a product drops its first-in-table-order choice, offers each issuer as a `Candidate` and serves the document of the one `describe` returns |
| An active introspection response is held until its `exp` and at most `cache_max_age`, keyed by the token's SHA-256, in a bounded cache; an inactive one is never held | `rfc7662 §4` ("MUST NOT be cached beyond" `exp`); the bounds are our own design (FerroBRIDGE #533) | none |
| Onward tokens are obtained by token exchange or the JWT bearer grant as the issuer's profile names, refused unless they pass the onward check of 3.16, cached by issuer, grant, subject and actor token, target, scope and extra parameters until the earlier `exp` (unless the onward table sets `cache = false`, which exchanges on every call for a performance self-test and never in production, #299), and never refreshed; only a `persons`, `patients` or `federation` issuer issues them, a `patients` one for a patient's own token that keeps its patient context | `rfc8693 §2.1`, `§2.2`, `§4.1`; `rfc7523 §2.1`, `§2.2`; `rfc8707 §2`; the check, the cache and the profile keys are our own design (#217) | a deployment sets `max_onward_lifetime` on each onward issuer, and `exchanges_from` and `person_mapping` on a federation issuer's table |
| An Entra ID groups overage is resolved by the `idp-entra` adapter, an optional feature a profile names by `adapter`, at the `getMemberObjects` URL it builds from the Graph root and the token's `oid` and `idtyp`, never at `_claim_sources`; every Graph failure is `GroupsUnavailable` carrying the status, the `Retry-After` or the timeout, under a 2 s budget of its own and with no cache (3.17) | Microsoft, "Access token claims reference", §Groups overage claim; "Optional claims reference", `idtyp`; Microsoft Graph v1.0 `directoryObject: getMemberObjects` and "Microsoft Graph throttling guidance"; the bounds are our own design (#221) | a deployment with users above the overage limit compiles `idp-entra`, sets `adapter = "idp-entra"` on its `entra` issuer, grants the Graph permission and registers the adapter |
| The eHDSI IdA and TRC are checked in this crate behind `ehdsi-assertion`, by our own exclusive canonicalization over `roxmltree` and `x509-parser` with `aws-lc-rs` verifying, in one accepted signature shape against wrapping; a trusted signer is an issuer URI with its seal certificate, revocation is the deployment's, and an inclusive prefix outside SAML Profile 10.0.0 §1.4.2 or a canonicalization other than Exc-C14N is refused (3.18) | eHDSI Cryptographic Algorithms 9.0.0 §2, §4.1; SAML Profile 10.0.0 §2, §4; X.509 Certificates Profile 7.0.0 §2.4, §3.1; SOG-IS ACM 1.3 §4.1, §5.2; the shape, the caps and the trust set are our own design (#294) | an authorization server acting for NCPeH-A compiles `ehdsi-assertion` and supplies the SMP-published seal certificates |
| An `@ID` is accepted as `urn:uuid:` or `_` followed by a UUID | SAML Profile 10.0.0 §2.1 writes a URN-encoded UUID, which SAML 2.0 Core §2.3.3's `xs:ID` cannot hold; accepting both is our own design (#294) | none |
| An eHDSI exchange is admitted once: the `ReplayGuard` keys it by the issuer and `ID` of the IdA and, past the discovery phase, of the TRC, and keeps it until the earliest window or session end plus 60 s; a guard is required to build a `Validator`, and one that cannot answer admits nothing | RFC 7522 §3, item 6; eHDSI Messaging Profile 10.0.0 §5.5.1 (the IdA is a supporting token) and SAML Profile 10.0.0 §6 (non-normative, the IdA's session); keying by the exchange is our own design | the authorization server acting for NCPeH-A supplies a store its replicas share (FerroHEALTH/FerroAUTH#317) |
| An eHDSI assertion whose `InclusiveNamespaces PrefixList` names a prefix outside SAML Profile 10.0.0 §1.4.2, such as the `xs` OpenSAML signers often list, is refused | eHDSI Cryptographic Algorithms 9.0.0 §4.1: "other prefixes than the ones defined in [SAML Profile] MUST NOT be used" | an NCP-B whose signer lists `xs` fixes its signer |

## 10. Verification

Every rule above is a test the crate carries before a product moves:

- the discovery order and the issuer mismatch, over `wiremock`;
- the key set: `use`, `key_ops`, `alg` and `kty` filtering, the `kid`
  match, the ambiguous no-`kid` case, the unknown-`kid` refetch and its
  interval, the max-age refetch, the failed read answering `503`;
- the token: each check of 3.3 as its own refusal with its own test, for a
  token minted under RS256, PS256, ES256, ES384 and EdDSA, and the `none`
  and HMAC refusals pinned as asserted negative tests;
- the scopes: the grammar, the v1 mapping, the out-of-order and unknown
  cases, the wildcard, the patient compartment, the union rule, the granular
  constraint without an evaluator;
- Basic: the colon and control-character rules, the UTF-8 decoding, the
  decoy timing, the scopes a user carries;
- the client credentials client: the three authentication methods, the
  assertion's claims and lifetime, the cache and its margin, the shared
  fetch, the one renewal on a `401`, the `rfc6749 §5.2` error body;
- the audit line: the field set, byte for byte, and the absence of every
  forbidden value under a token, a Basic credential and a refusal;
- the error model: every status and challenge string of 3.7, pinned as the
  contract the products' existing tests already hold.
- sender-constrained tokens: the RFC 9449 Figure 2, 4, 9, 13 and 14 and
  RFC 8705 Figure 2 and Appendix A examples, each check of `rfc9449 §4.3`
  as its own refusal, the replay refusal over a shared and an in-memory
  store, the certificate binding, and the `cnf` token under `Bearer` (3.15);
- the onward grants: RFC 8693 §2.3 Figures 2 and 3 and Appendix A Figures
  10 to 18, RFC 7523 §4 with the §2.2 client assertion, Microsoft's
  on-behalf-of "Second case", success and error examples and Keycloak's
  example request and Examples 1 to 3, then every check of 3.16 as its own
  refusal under the standards-only, `entra` and `keycloak` profiles against
  a harness token endpoint, the federation route, and the cache (3.16);
- the `idp-entra` adapter, behind its feature and after the generic suite:
  the "Access token claims reference" overage example and `hasgroups`
  resolved at the adapter-built `getMemberObjects` URL against a
  `wiremock` Graph that records `_claim_sources` is never called, the
  `servicePrincipals` URL by `idtyp`, the `429` with its `Retry-After`, a
  refused permission, a refused Graph token, the timeout, the size bound,
  the renewal on a `401`, no cache, and the p99 perf case (3.17);

The vendored specifications are read by the design and by the tests that
cite them; `scripts/checks/versions.sh` holds the trees to their provenance,
so the corpus cannot drift under the citations.

## 11. `ferrohealth-authz`: the policy decision

`ferrohealth-smart` says who the caller is and what it was granted;
`ferrohealth-authz` decides what that subject may do with an object. The
vocabulary is NIST SP 800-162 (`nist-sp-800-162 §2`, §3): attribute-based
access control over subject, object and environment attributes, a policy
decision point (PDP) and the policy enforcement point (PEP) that consults it.
The code came from FerroEHR (`app/ferroehr-rest/src/extensions/access/authz/`),
generalised so FerroFED and FerroPIX use it too (owner decision 2026-10-25).

- **The request.** `request::Subject` is read from the caller
  `ferrohealth-smart` admitted: its subject id, its caller kind (3.14), roles
  (3.11), scopes, and the claims a product names as subject attributes. `request::Request` names an
  action, a resource type, resource attributes and context attributes. A
  resource attribute may be a set, when one operation touches several objects;
  the engine decides every combination of one value per set and permits only
  when every combination is permitted, the first deny ending the evaluation.
  An empty set is refused when the request is built, since it would leave
  nothing to decide. No specification governs the fan-out: our own design.
- **The decision.** `request::Decision` is `Permit` or `Deny`, each with the
  policies that made it. An engine that cannot decide answers
  `engine::AuthzError`, never a decision, and a product answers that as a
  fault of its own (a `500`): the PDP decides (`nist-sp-800-162 §3.2.1`), and
  failing closed when it cannot is our own design.
- **Cedar** (feature `cedar`). Policies are in the Cedar language
  (`cedar-docs`, the language reference): deny by default, a `forbid`
  overriding every `permit`. The schema is written from the product's
  `cedar::Model` (the subject attributes, each resource type with its
  attributes, each action with the resource types it applies to, the context
  attributes), so a policy can name only what the product sends; the principal
  is `User` with `roles`, `scopes` and the caller `kind` by the name the audit
  line records, which the model may not redeclare. Policies are validated strictly at load
  and at every reload; a reload that does not validate keeps the set in force.
  Cedar skips a policy that errors during evaluation and reports it in the
  diagnostics; the engine answers such an evaluation with an error, since a
  skipped `forbid` would otherwise stop forbidding. Entity ids are built with
  the API, never by formatting a policy string, so no subject can forge
  another principal.
- **A remote PDP** (feature `remote`). One `POST {server}{policy}` per
  combination with a flat JSON object of the attributes the resource type's
  binding names; `200` permits, a `4xx` denies, and every other answer, a
  redirect included, is no decision. Under a client credentials grant the
  call carries `ferrohealth-smart`'s token and is sent once more under a new
  token on a `401`. `RemotePdp::with_client` takes the product's HTTP
  client, built from the integration's endpoint table with its TLS, and that
  table's `retry`: a call that did not reach the point, timed out or met a
  `5xx` is tried again with a doubling, bounded backoff, and a `4xx`, a
  redirect or a refused token is not. The wire contract and the retry rule
  are our own design.
- **Dependencies.** Without a feature the crate holds the request model and
  the trait alone. `cedar` adds `cedar-policy`, `arc-swap` and the Tokio
  timer of the reload; `remote` adds the HTTP client through
  `ferrohealth-smart`'s `fetch` and the Tokio timer of the retry backoff.
- **Releases.** The crate keeps its own version line and changelog,
  released by the tag `ferrohealth-authz-vX.Y.Z` through the same release and
  publish lanes as `ferrohealth-smart` (`docs/release.md`).

| Decision | Ground | Owner items |
|---|---|---|
| The policy decision is its own crate in this repository, `ferrohealth-authz`, on its own version line, reading `ferrohealth-smart`'s subject | owner decision 2026-10-25; `nist-sp-800-162 §2`, §3 | FerroEHR moves its `authz/` here and deletes its copy |
| A request with a set attribute is permitted only when every combination is; an engine that cannot decide answers an error the PEP fails closed on | our own design | none |

## 12. `ferrohealth-session`: the console sign-in and session

Every operator console of the family signs its operator in at an OpenID
Provider and keeps a session the browser holds a cookie to. The relying
party itself is `ferrohealth_smart::oidc` (#131), which keeps no state
between calls; `ferrohealth-session` keeps that state, in one crate in place
of the five copies the consoles of FerroBRIDGE, FerroFED, FerroPIX and
FerroTERM and the FerroEHR viewer carried (owner decision 2026-11-03, #177).

- **The flow.** `GET /login` mints the `state`, the `nonce` and the PKCE
  verifier through the relying party and keeps them as a pending sign-in
  with the page `?return=` names, held to one of the console's own
  (`rfc3986 §4.2`); `GET /auth/callback` takes it once, and the relying party
  holds the returned `state` to it (`rfc6749 §10.12`), exchanges the code
  with the verifier (`rfc7636 §4.5`) and checks the ID Token (OpenID Connect
  Core 1.0 §3.1.3.7). `POST /logout` ends the session, revokes its refresh
  token, or its access token when there is none (`rfc7009 §2.1`), and sends
  the operator to the end-session endpoint with the session's ID Token as
  `id_token_hint` (RP-Initiated Logout 1.0 §2); a session that holds no ID
  Token was never signed in at the provider and lands on the console's
  signed-out page. The four paths are the same on every console.
- **The stores.** `memory` keeps two bounded pools in the process: a full
  pending pool drops its oldest sign-in, and a full session pool refuses a
  new session and keeps every live one. `sealed` keeps the whole record in
  one cookie sealed with AES-256-GCM (the `cookie` crate's private jar), so
  a console that runs as several instances with no shared store opens it
  anywhere; a cookie that does not open is no session, and one larger than
  the 4096 bytes a browser keeps (`rfc6265 §6.1`) is refused when it is
  sealed. Every cookie is `HttpOnly`, `SameSite=Lax` and, unless turned off,
  `Secure` with the `__Host-` prefix (RFC 6265bis §4.1.3.2, §5.4.7).
- **The lifetimes.** The absolute lifetime runs from the sign-in time the
  session carries and nothing moves it; the idle lifetime runs from the last
  request that counted as activity and never past the absolute end; an
  access token no refresh token can replace ends the session when it
  expires. The session watch (`GET`/`POST /session`) answers FerroUI's wire
  `{"idle": s, "absolute": s}`: a `GET` never counts as activity, a `POST`
  does, and `401` says the session is gone.
- **The refresh.** A memory session that holds a refresh token renews its
  access token within 60 seconds of its expiry, at most half its lifetime
  (`rfc6749 §6`), one refresh per session at a time so a rotated refresh
  token is spent once; a refusal ends the session, and a provider that is
  not reached is reported, never read as a success.

| Decision | Ground | Owner items |
|---|---|---|
| The console sign-in and session is its own crate in this repository, `ferrohealth-session`, on its own version line, over `ferrohealth-smart`'s relying party | owner decision 2026-11-03 | each console moves onto it and deletes its copy |
| A sealed store refuses `offline_access` when the configuration loads | `rfc6749 §10.4`: a refresh token sealed into a browser cookie outlives a sign-out that cannot reach it (owner decision 2026-11-03) | a console that wants refresh tokens uses the memory store |
| A sealed store without a key is refused when the configuration loads; there is no per-process key | our own design, fail closed (owner decision 2026-11-03) | the FerroEHR viewer's deployments set `session.key` |
| One route set, `/login`, `/auth/callback`, `/logout` and `/session`, on every console | our own design (owner decision 2026-11-03) | FerroTERM and the FerroEHR viewer change the redirect URI registered at their provider |
| The store, the lifetimes and the watch route | no specification governs them: our own design, held to the OWASP Session Management Cheat Sheet | none |
