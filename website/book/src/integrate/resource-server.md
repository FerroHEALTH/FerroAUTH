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
  is;
- the `roles` claim (RFC 9068 §2.2.3.1), when the server takes roles from
  its issuer: the person's roles at the identity provider that a
  `[[ferrosmart.role]]` names, carried by every token of a user flow and
  never by a Backend Services token. The server decides itself whether it
  trusts FerroSMART for roles (FerroEHR's `role_issuers`), and a privileged
  role such as an emergency access role needs its own `[[ferrosmart.role]]`
  table to reach it.

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
default except three: `typ` is `at+jwt` alone, `scope` is required, and a
patient's own token is read as the patient. `delegates` lists the SMART apps
the product admits for a person, a patient's apps among them:

```toml
[[auth.issuer]]
issuer = "https://smart.example.org"
kind = "persons"
profile = "ferrosmart"
audience = ["https://ehr.example.org/openehr/v1"]
delegates = [{ client = "growth-chart" }]
```

The same table reads a Backend Services token as a system caller, because
its `sub` is its `client_id`. A token through a listed app is the patient's
own access when its `fhirUser` is `Patient/<x>`, its `patient` is `x`, and
its scopes are `patient/` with no `user/` or `system/` scope; any other
person's token, a professional's with `patient/` scopes included, is read as
the professional's. The product's own SMART document describes
FerroSMART, and its own rules still apply on top of the token's scopes.
Each product's book has the details of its `[auth]` section.

For a server of your own in Rust, add the crate with its axum layer:

```sh
cargo add ferrohealth-smart -F axum
```

Its documentation is on [docs.rs](https://docs.rs/ferrohealth-smart).
