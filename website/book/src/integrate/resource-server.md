<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# A server behind FerroSMART

A FHIR or openEHR server sits behind FerroSMART as a resource server: it
reads the tokens FerroSMART issues and never sees the person log in. The
identity provider runs upstream for login only.

```text
 browser            SMART app           FerroSMART           identity provider
    |  1. launch        |                    |                       |
    |------------------>| 2. /authorize      |                       |
    |                   |    aud = the base  |                       |
    |<---------------------------------------|  3. login             |
    |--------------------------------------------------------------->|
    |<---------------------------------------------------------------|
    |  4. picker and consent                 |                       |
    |--------------------------------------->|                       |
    |                   |<- 5. code, token ->|                       |
    |                   |  6. API call with the access token         |
    |                   |------------------------------> the server
```

## On FerroSMART's side

Name the server's base as a resource, so a launch can use it as `aud`:

```toml
[[ferrosmart.resource]]
base = "https://ehr.example.org/openehr/v1"   # or the FHIR base
kind = "openehr"                               # or "fhir"
subject_namespace = "examples"                 # openEHR only: the picker's EHR lookup
```

When the platform also serves FHIR, pair the two bases. The picker then
finds the patient at the FHIR server and their EHR at the openEHR server,
and the app gets both `patient` and `ehrId`:

```toml
[[ferrosmart.resource]]
base = "https://ehr.example.org/fhir"

[[ferrosmart.resource]]
base = "https://ehr.example.org/openehr/v1"
kind = "openehr"
subject_namespace = "examples"
fhir_base = "https://ehr.example.org/fhir"     # the platform's FHIR base, configured above
subject_system = "urn:example:mrn"             # the Patient.identifier that names the EHR's subject
```

## On the server's side

The server checks each token as an RFC 9068 JWT:

- the signature with a key from FerroSMART's `jwks_uri`, refetched on an
  unknown `kid`, so a [rotated key](../operate/keys.md) is found;
- `typ` `at+jwt`, `iss` FerroSMART's issuer, `aud` its own base, `exp`;
- the `scope` claim against what the request needs, and the context
  claims `patient`, `encounter`, `fhirUser` and `ehrId` for whose data it
  is.

A server that cannot read JWTs introspects instead
([the flows](flows.md#refresh-introspection-and-revocation)), as a
registered client whose ceiling lists `system/introspect`.

The server serves its own `.well-known/smart-configuration`, as SMART asks
of every FHIR endpoint that requires authorization, and names FerroSMART's
`authorization_endpoint` and `token_endpoint` in it, so an app that starts
at the server finds FerroSMART.

## A FerroHEALTH product

Every FerroHEALTH product does this through `ferrohealth-smart`, the crate
the FerroSMART repository publishes. It trusts FerroSMART in one `persons`
issuer table under the `ferrosmart` preset, which keeps every RFC 9068
default except two: `typ` is `at+jwt` alone and `scope` is required.
`delegates` lists the SMART apps the product admits for a person:

```toml
[[auth.issuer]]
issuer = "https://smart.example.org"
kind = "persons"
profile = "ferrosmart"
audience = ["https://ehr.example.org/openehr/v1"]
delegates = [{ client = "growth-chart" }]
```

The same table reads a Backend Services token as a system caller, because
its `sub` is its `client_id`. The product's own SMART document describes
FerroSMART, and its own rules still apply on top of the token's scopes.
Each product's book has the details of its `[auth]` section.

For a server of your own in Rust, add the crate with its axum layer:

```sh
cargo add ferrohealth-smart -F axum
```

Its documentation is on [docs.rs](https://docs.rs/ferrohealth-smart).
