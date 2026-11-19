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

FerroSMART authenticates to every provider with `private_key_jwt` (OpenID
Connect Core 1.0 §9): a JWT signed by its assertion key, configured under
`[ferrosmart.upstream.private_key_jwt]`. That table is required, and a
client secret is refused at start. The assertion key is a key of its own,
never a token signing key, and FerroSMART publishes it at
`{issuer}/upstream-jwks` for a provider that reads a key set
([keys and rotation](../operate/keys.md#the-assertion-keys)).

Each assertion names the provider's issuer as its only audience (`aud`)
and has the type `client-authentication+jwt`, as RFC 10070 §4 requires.
Keycloak and ZITADEL accept this by their source code. Entra ID and Okta
document the token endpoint URL as `aud`; RFC 10070 §6 says a client that
follows the update works with them too. Verify it on your tenant before
production.

Every provider below is described in the same shape: login, client
authentication, `fhirUser`, roles, and how the setup is tested.

| Provider | Login | Client authentication | `fhirUser` | Roles | Tested by |
|---|---|---|---|---|---|
| Keycloak | the realm's login form | Signed JWT, reading `{issuer}/upstream-jwks` | a user attribute mapper | a realm role mapper, `roles` | a live launch in CI, and the compose quickstart |
| ZITADEL | the Login v2 UI | Private Key JWT, with a key ZITADEL generates | an Actions v2 target, from user metadata | the project role claim | a live launch in CI |
| Microsoft Entra ID | the tenant's sign-in | a certificate of the assertion key | a directory extension attribute | app roles, `roles` | a contract test against Entra ID's documents |
| Okta | the org's sign-in, `default` authorization server | Public key / Private key, the JWK of `{issuer}/upstream-jwks` | a custom claim | a groups claim, `groups` | a contract test against Okta's documents |

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
| Login | the client `ferrosmart`, the standard flow with PKCE `S256`, implicit and direct access grants off, redirect URI `{issuer}/callback` |
| Client authentication | confidential, client authenticator `client-jwt` with a JWKS URL: FerroSMART's `{issuer}/upstream-jwks`, signed `RS256` |
| `fhirUser` | a user attribute mapper writes the attribute `fhir_user` into the ID Token |
| Roles | a realm role mapper, multivalued, writes `roles` into the ID Token; the realm role `clinician` |
| Tested by | a standalone launch in CI through Keycloak's login form, and the compose quickstart lane |

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
| Login | the OIDC web app `ferrosmart-login`, the code flow with PKCE `S256`, one redirect URI `{issuer}/callback`, roles and user info in the ID Token |
| Client authentication | Private Key JWT, with an application key ZITADEL generates; FerroSMART signs with it under ZITADEL's key id |
| `fhirUser` | an Actions v2 execution on `preuserinfo` that adds `fhirUser` from the user's metadata |
| Roles | the project `ferrosmart` with role assertion on and the role `clinician`, in the claim `urn:zitadel:iam:org:project:ferrosmart:roles`, an object whose member names are the roles |
| Tested by | a standalone launch in CI through ZITADEL |
| Audience | ZITADEL adds the project to the ID Token's `aud`, so FerroSMART trusts it |

```toml
[ferrosmart.upstream]
issuer = "https://zitadel.example.org"
client_id = "<the generated client id>"
scopes = ["openid", "profile"]
fhir_user_claim = "fhirUser"
role_claims = ["urn:zitadel:iam:org:project:ferrosmart:roles"]
trusted_audiences = ["ferrosmart"]

[ferrosmart.upstream.private_key_jwt]
algorithm = "RS256"

[ferrosmart.upstream.private_key_jwt.keys]
private_key_file = "/run/secrets/zitadel-application-key.pem"
kid = "<the key id ZITADEL gave the key>"
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
| Login | a single-tenant app registration, the authority `https://login.microsoftonline.com/<tenant id>/v2.0` as the `issuer`, platform Web with the redirect URI `{issuer}/callback`, the code flow with PKCE `S256` |
| Client authentication | a certificate of FerroSMART's current assertion key, uploaded to the registration; each assertion names it by `x5t#S256`, signed `PS256` |
| `fhirUser` | a directory extension attribute `fhirUser`, set per user, as an ID Token optional claim, which Entra ID emits as `extn.fhirUser` |
| Roles | the app role `clinician`, assigned to people or to groups under Enterprise applications; the ID Token carries it in `roles` |
| Tested by | a contract test that runs the example against Entra ID's discovery document, key set and token answer |

FerroSMART reads roles from app roles alone, never from the `groups`
claim: a person in more groups than the token holds gets an overage
reference to Microsoft Graph in place of `groups`, which FerroSMART does
not follow, and app roles hold the same values in every tenant
(`howto-add-app-roles-in-apps.md`, App roles vs. groups). Assigning a group
to an app role gives every member that role in `roles`. Whether assigning a
group, rather than each person, needs a paid Microsoft Entra ID licence
(P1 or higher) is not stated in the Microsoft pages FerroSMART vendors, so
check your tenant's licence before you plan on group assignment.

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
FerroSMART logs in the people of one tenant. To rotate, upload the next
key's certificate before the ring makes it current.

## Okta

Okta is a hosted service as well; the contract tests run
`app/ferrosmart/examples/okta/ferrosmart.toml` against the documents Okta
publishes.

| At Okta | Value |
|---|---|
| Login | a Web Application integration with the authorization code grant and PKCE `S256`, `{issuer}/callback` as the one sign-in redirect URI, at the custom authorization server `default`, issuer `https://<your Okta domain>/oauth2/default` |
| Client authentication | Public key / Private key: add the JWK FerroSMART publishes at `{issuer}/upstream-jwks` to the integration's public keys; assertions are signed `RS256` |
| `fhirUser` | a custom claim `fhir_user` in the ID Token, always, reading the person's `fhirUser` profile attribute |
| Roles | a groups claim `groups` in the ID Token, always, filtered to FerroSMART's role groups; the group `clinician`, assigned to the app integration |
| Tested by | a contract test that runs the example against the documents Okta publishes |

```toml
[ferrosmart.upstream]
issuer = "https://example.okta.com/oauth2/default"
client_id = "<the client id>"
scopes = ["openid", "profile"]
fhir_user_claim = "fhir_user"
role_claims = ["groups"]

[ferrosmart.upstream.private_key_jwt]
algorithm = "RS256"

[ferrosmart.upstream.private_key_jwt.keys]
private_key_file = "/run/secrets/upstream-assertion.pem"
```

Use the custom authorization server, since only that one takes a custom
claim in the ID Token by Okta's written procedure, and keep the groups
filter narrow: a groups claim holds at most 100 groups. To rotate, add the
next key's JWK to the integration before the ring makes it current.
