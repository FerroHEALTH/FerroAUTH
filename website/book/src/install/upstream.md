<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Identity providers

A person logs in at an OpenID Connect provider upstream of FerroSMART, and
FerroSMART is a client of that provider. Any provider that publishes an
OpenID Connect discovery document works; no code in FerroSMART knows a
vendor. Four have a tested setup, and each section below says what to
configure at the provider and in `[ferrosmart.upstream]`.

## What every provider needs

At the provider, register FerroSMART as a confidential web client:

- the authorization code flow, with PKCE `S256` (FerroSMART sends a
  challenge on every request);
- one redirect URI, FerroSMART's `{issuer}/callback`, matched exactly;
- an ID Token claim with the person's `fhirUser`, such as
  `Practitioner/123` or an absolute URL, when apps ask for `fhirUser`;
- an ID Token claim with the person's roles, which
  [`[[ferrosmart.role]]`](../configure/clients.md#roles) maps to scopes;
- optionally FerroSMART's `{issuer}/backchannel-logout` as the back-channel
  logout URI, so a logout at the provider ends the person's
  `online_access` grants.

FerroSMART authenticates to the provider in one of three ways:

| `[ferrosmart.upstream]` | How FerroSMART authenticates | Use it for |
|---|---|---|
| neither key below | A public client with PKCE alone | A provider that allows it |
| `client_secret_file` | The client secret as HTTP Basic (RFC 6749 §2.3.1) | Okta, ZITADEL |
| `[ferrosmart.upstream.private_key_jwt]` | A JWT signed by FerroSMART's assertion key (OpenID Connect Core 1.0 §9) | Keycloak, Microsoft Entra ID |

A secret and `private_key_jwt` together are refused at start. The
assertion key is a key of its own, never a token signing key, and FerroSMART
publishes it at `{issuer}/upstream-jwks` for a provider that reads a key set
([keys and rotation](../operate/keys.md#the-assertion-keys)).

FerroSMART checks the provider's ID Token by OpenID Connect Core 1.0
§3.1.3.7, refuses one without the `nonce` it sent, and reads only the
claims you name. The person's `sub` at FerroSMART is derived from the
provider's issuer and `sub`, so it never reaches a resource server.

## Keycloak

Keycloak runs upstream in a compose overlay of the quickstart. From a
checkout, with the two extra secret files the overlay's header lists:

```sh
docker compose -f compose.yaml -f compose.keycloak.yaml up
```

Sign in as `clinician` with the password in
`secrets/keycloak_user_password`. The realm is
`app/ferrosmart/examples/keycloak/ferrosmart-realm.json`, and FerroSMART's
side is `ferrosmart.toml` beside it. The overlay runs Keycloak in
development mode and both servers on plain `http` on `localhost`; a
deployment serves both over TLS on their own names.

| At Keycloak | Value |
|---|---|
| Client `ferrosmart` | confidential, client authenticator `client-jwt` with a JWKS URL: FerroSMART's `{issuer}/upstream-jwks`, signed `RS256` |
| Flows | the standard flow on; implicit and direct access grants off |
| PKCE | `S256` |
| Redirect URI | `{issuer}/callback` |
| `fhir_user` | a user attribute mapper into the ID Token |
| `roles` | a realm role mapper, multivalued, into the ID Token |
| Realm role | `clinician` |

```toml
[ferrosmart.upstream]
issuer = "https://keycloak.example.org/realms/ferrosmart"
client_id = "ferrosmart"
scopes = ["openid"]
fhir_user_claim = "fhir_user"
role_claims = ["roles"]

[ferrosmart.upstream.private_key_jwt]

[ferrosmart.upstream.private_key_jwt.keys]
private_key_file = "/run/secrets/upstream_assertion_key"
```

## ZITADEL

ZITADEL runs upstream in a compose overlay too, with its Login v2 UI and
its own PostgreSQL. From a checkout, with the three extra secret files the
overlay's header lists:

```sh
docker compose -f compose.yaml -f compose.zitadel.yaml up
```

A bootstrap container runs `app/ferrosmart/examples/zitadel/bootstrap.sh`
once: it makes the project with its role, the application, the user and
the action that writes `fhirUser`, and writes FerroSMART's configuration
with the client id ZITADEL generated. Log in at
`http://localhost:3000/ui/v2/login`.

| At ZITADEL | Value |
|---|---|
| Project | `ferrosmart`, role assertion on, the role `clinician` |
| Application | an OIDC web app, the code flow, `client_secret_basic`, one redirect URI `{issuer}/callback`, roles and user info in the ID Token |
| `fhirUser` | an Actions v2 execution on `preuserinfo` that adds `fhirUser` from the user's metadata |
| Roles | the claim `urn:zitadel:iam:org:project:ferrosmart:roles`, an object whose member names are the roles |
| Audience | ZITADEL adds the project to `aud`, so FerroSMART trusts it |

```toml
[ferrosmart.upstream]
issuer = "https://zitadel.example.org"
client_id = "<the generated client id>"
client_secret_file = "/run/secrets/zitadel_client_secret"
scopes = ["openid", "profile"]
fhir_user_claim = "fhirUser"
role_claims = ["urn:zitadel:iam:org:project:ferrosmart:roles"]
trusted_audiences = ["ferrosmart"]
```

`trusted_audiences` names the audiences beside FerroSMART's client id that
an ID Token may carry; an ID Token with several audiences must then name
the client in `azp`.

## Microsoft Entra ID

Entra ID is a hosted service, so no example runs it; the contract tests run
FerroSMART's side, `app/ferrosmart/examples/entra/ferrosmart.toml`, against
the discovery document, key set and token answer Entra ID publishes.

| At Entra ID | Value |
|---|---|
| App registration | single tenant |
| Authority | `https://login.microsoftonline.com/<tenant id>/v2.0`, the `issuer` |
| Redirect URI | platform Web, `{issuer}/callback` |
| Credential | a certificate of FerroSMART's current assertion key |
| App role | `clinician`, assigned to people under Enterprise applications; the ID Token carries it in `roles` |
| `fhirUser` | a directory extension attribute `fhirUser`, set per user, as an ID Token optional claim, which Entra ID emits as `extn.fhirUser` |

```toml
[ferrosmart.upstream]
issuer = "https://login.microsoftonline.com/<tenant id>/v2.0"
client_id = "<the application (client) id>"
scopes = ["openid", "profile"]
fhir_user_claim = "extn.fhirUser"
role_claims = ["roles"]

[ferrosmart.upstream.private_key_jwt]
algorithm = "PS256"
certificate_file = "/run/secrets/upstream-assertion.crt"

[ferrosmart.upstream.private_key_jwt.keys]
private_key_file = "/run/secrets/upstream-assertion.pem"
```

Three choices hold here. Roles come from app roles, never groups, because a
person in many groups gets an overage pointer instead of the groups. The
multitenant authorities `/common` and `/organizations` are refused, since
their metadata names an issuer other than the one it was read under: one
FerroSMART logs in the people of one tenant. A client secret works as well,
but Entra ID advises a certificate in production. To rotate, upload the
next key's certificate before the ring makes it current.

## Okta

Okta is a hosted service as well; the contract tests run
`app/ferrosmart/examples/okta/ferrosmart.toml` against the documents Okta
publishes.

| At Okta | Value |
|---|---|
| Authorization server | the custom authorization server `default`, issuer `https://<your Okta domain>/oauth2/default` |
| App integration | a Web Application with the authorization code grant |
| Redirect URI | `{issuer}/callback` as the one sign-in redirect URI |
| Client authentication | the client secret, as HTTP Basic |
| `fhir_user` | a custom claim in the ID Token, always, reading the person's `fhirUser` profile attribute |
| `groups` | a groups claim in the ID Token, always, filtered to FerroSMART's role groups |
| Group | `clinician`, assigned to the app integration |

```toml
[ferrosmart.upstream]
issuer = "https://example.okta.com/oauth2/default"
client_id = "<the client id>"
client_secret_file = "/run/secrets/okta_client_secret"
scopes = ["openid", "profile"]
fhir_user_claim = "fhir_user"
role_claims = ["groups"]
```

Use the custom authorization server, since only that one takes a custom
claim in the ID Token by Okta's written procedure, and keep the groups
filter narrow: a groups claim holds at most 100 groups.
