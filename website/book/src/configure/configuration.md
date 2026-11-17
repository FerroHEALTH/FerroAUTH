<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Configuration

FerroSMART reads one configuration tree, in this order, the later winning:

1. the TOML file `--config` names, or `FERROSMART_CONFIG` does;
2. the environment, every key as `FERROSMART__<SECTION>__<KEY>`, with an
   index for an element of an array of tables
   (`FERROSMART__FERROSMART__RESOURCE__0__BASE`);
3. `--set key=value` pairs on the command line.

Every table refuses a key it does not know, so a typing error fails the
start instead of being ignored. Every secret has a `_file` form that names a
file holding it, such as `url_file` beside `url`; use the file form, so a
secret stays out of the environment. `ferrosmart config check` prints the
tree as FerroSMART reads it, every secret masked, and exits non-zero naming
the first key it cannot run with.

A duration is written as `"5min"`, `"8h"` or `"30d"`.

## `[server]`

The listener and the request stack every FerroHEALTH server shares.

| Key | Default | What it is |
|---|---|---|
| `listen` | `127.0.0.1:8080` (the image sets `0.0.0.0:8080`) | The address the listener binds |
| `base_path` | empty | The path every route is served under; it must equal the issuer's path |
| `request_timeout` | `30s` | How long one request may take before a `408` |
| `header_read_timeout` | `30s` | How long a client may take to send its request head |
| `idle_timeout` | `2min` | How long an idle connection is kept |
| `body_limit` | 1 MiB | The largest request body read before a `413` |
| `drain_delay` | `0s` | How long readiness stays withdrawn before the listener closes |
| `shutdown_timeout` | `10s` | How long requests in flight may take once the listener closed |
| `max_concurrent_requests` | 256 | Requests served at once before a `503` with `Retry-After` |
| `trusted_proxies` | none | The reverse proxies whose forwarded client address is believed |
| `caller_rate` | none | A request rate per caller, refused past it |
| `compression` | `true` | Whether responses are compressed for a client that accepts it |
| `[server.tls]` | none | TLS on the listener: `certificate_file`, `key_file`, `min_version`, and client certificates; unset, the listener speaks plain HTTP behind a proxy that terminates TLS |

The table is the `ferrohealth-server` crate's, documented on
[docs.rs](https://docs.rs/ferrohealth-server).

## `[telemetry]`

The console log. `format` is `auto` (readable on a terminal, JSON
otherwise), `pretty` or `json`; `filter` is a `RUST_LOG` filter such as
`info`, and `RUST_LOG` sets it too. No line carries a token, a code, a
secret or an assertion.

## `[ferrosmart]`

| Key | Default | What it is |
|---|---|---|
| `issuer` | required | The issuer identifier (RFC 8414 §2): an `https` URL with no query or fragment, or `http` on a loopback host. Its path is `[server] base_path`. Every document repeats it exactly |
| `access_token_lifetime` | `5min` | How long an access token lives, for every grant; at most one hour (SMART App Launch 2.2.0, App Launch) |
| `refresh_idle` | `30d` | How long an `offline_access` refresh token lasts unused; each refresh starts it again |
| `online_idle` | `8h` | How long an `online_access` refresh token lasts unused, and never past the person's login at the identity provider |

None of the three lifetimes may be zero.

## `[ferrosmart.database]`

| Key | Default | What it is |
|---|---|---|
| `url_file` | | A file holding the PostgreSQL connection URL |
| `url` | | The URL itself; set one of the two |
| `max_connections` | 16 | The most connections one replica holds |

Every piece of state is in the database, so any number of replicas share
one. Migrations ship in the binary and run at start.

## `[ferrosmart.keys]`

The RSA keys that sign every access token and ID Token under `RS256`
([keys and rotation](../operate/keys.md)).

| Key | Default | What it is |
|---|---|---|
| `private_key_file` | required | The PEM file of the key that signs |
| `kid` | its RFC 7638 thumbprint | The `kid` the key is published under |
| `next_private_key_file` | none | The key a rotation makes current, published ahead and never signing |
| `previous_private_key_file` | none | The key that signed before a rotation, published and never signing |
| `previous_key_overlap` | `0s` | How long the previous key stays published; `"0s"` for as long as it is configured |

## `[[ferrosmart.resource]]`

Each FHIR or openEHR server a token may be for. Its base URL is the `aud`
of the tokens issued for it. At least one is required, and no base twice.

| Key | What it is |
|---|---|
| `base` | The server's base URL as its clients name it: `https`, or `http` on a loopback host, no query or fragment |
| `kind` | `fhir` or `openehr` |
| `subject_namespace` | openEHR only: the namespace the server's EHRs name their subjects in, which the patient picker looks an EHR up by. Unset, the picker is not offered at that base |

## `[ferrosmart.upstream]`

The OpenID Connect provider people log in at
([identity providers](../install/upstream.md)). Without this table, nobody
logs in and FerroSMART answers Backend Services alone.

| Key | What it is |
|---|---|
| `issuer` | The provider's issuer, whose discovery document FerroSMART reads at start |
| `client_id` | The client FerroSMART is registered as at the provider |
| `scopes` | The scopes FerroSMART asks for, `openid` among them |
| `fhir_user_claim` | The ID Token claim holding the person's `fhirUser`; empty for none |
| `role_claims` | The ID Token claims holding the person's roles, each a dotted path; a claim name with a dot is read whole first |
| `trusted_audiences` | Audiences an ID Token may carry beside the client id, such as a project the provider adds; empty trusts none |

`[ferrosmart.upstream.private_key_jwt]` is required: FerroSMART
authenticates to the provider with a signed assertion (`private_key_jwt`)
and takes no client secret.

| Key | What it is |
|---|---|
| `algorithm` | The JWS algorithm the provider's registration names; `RS256` by default |
| `certificate_file` | The X.509 certificate of the current assertion key, for a provider that knows the key by its certificate; each assertion then names it by `x5t#S256` |
| `[ferrosmart.upstream.private_key_jwt.keys]` | The assertion ring, with the same keys as `[ferrosmart.keys]`; it may share no key with the token ring. Its `kid` is the id the provider knows the key by, such as ZITADEL's key id |

## `[[ferrosmart.role]]` and `[[ferrosmart.client]]`

The policy: what each role may be granted and which clients exist.
[Clients, roles and consent](clients.md) describes both tables.

## `[ferrosmart.branding]`

The deployment's own words on the pages. Content, never code.

| Key | What it is |
|---|---|
| `name` | The name the pages carry, such as the hospital's |
| `consent_text` | The deployment's words on the consent page, such as what it does with the access a person gives |
| `smart_style_url` | The `smart_style_url` every token response carries: an `https` URL of the deployment's SMART style document; empty for none |

## `[ferrosmart.audit]`

How FerroSMART names itself in its [audit records](../operate/audit.md), and
where it forwards them.

| Key | What it is |
|---|---|
| `source_id` | FerroSMART as the recording system, `AuditEvent.source.observer`; empty takes the issuer's host |
| `site` | The site FerroSMART runs at, `AuditEvent.source.site` |
| `[ferrosmart.audit.feed]` | An Audit Record Repository: `url`, an `https` FHIR base the records are created under as `[base]/AuditEvent`, with `timeout`, `connect_timeout`, `retry`, `tls` and `credentials` (Basic, or an OAuth 2.0 client credentials grant under `credentials.oauth`). Unset, the records stay in FerroSMART's own store |

## A whole file

```toml
[ferrosmart]
issuer = "https://smart.example.org"

[ferrosmart.database]
url_file = "/run/secrets/ferrosmart-db-url"

[ferrosmart.keys]
private_key_file = "/run/secrets/rs256.pem"

[[ferrosmart.resource]]
base = "https://ehr.example.org/fhir"
kind = "fhir"

[ferrosmart.upstream]
issuer = "https://idp.example.org/realms/hospital"
client_id = "ferrosmart"
scopes = ["openid", "profile"]
fhir_user_claim = "fhir_user"
role_claims = ["roles"]

[ferrosmart.upstream.private_key_jwt]

[ferrosmart.upstream.private_key_jwt.keys]
private_key_file = "/run/secrets/upstream-assertion.pem"

[[ferrosmart.role]]
name = "clinician"
scopes = ["user/Patient.rs", "user/Observation.rs"]

[[ferrosmart.client]]
client_id = "growth-chart"
name = "Growth chart"
kind = "public"
redirect_uris = ["https://growth-chart.example.org/callback"]
scopes = ["openid", "fhirUser", "launch", "launch/patient", "patient/Observation.rs"]
grant_types = ["authorization_code"]

[ferrosmart.branding]
name = "Example Hospital"

[ferrosmart.audit]
site = "Example Hospital"
```
