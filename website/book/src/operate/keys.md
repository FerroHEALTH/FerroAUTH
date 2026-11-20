<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Keys and rotation

FerroSMART holds two rings of keys, each for one purpose, so a key of one
kind signs nothing the other is trusted for (RFC 8725 §3.12):

| Ring | Configured in | Published at | Signs |
|---|---|---|---|
| The token keys | `[ferrosmart.keys]` | `{issuer}/jwks`, which every discovery document names | Access tokens and ID Tokens |
| The assertion keys | `[ferrosmart.upstream.oidc.private_key_jwt.keys]` | `{issuer}/upstream-jwks`, which no discovery document names | FerroSMART's own client assertions to the identity provider |

The two rings may share no key; FerroSMART refuses to start when they do.
Each key is a PEM file from a mounted secret. The private key never enters
the database.

## The token keys

Tokens are signed `RS256`, the algorithm RFC 9068 §2.1 and OpenID Connect
Discovery 1.0 §3 have every authorization server support and SMART signs
ID Tokens with. `none` and HMAC never sign. One ring signs both access
tokens and ID Tokens; their `typ` (`at+jwt` against `JWT`) keeps an ID Token
from passing as an access token.

Make a key with OpenSSL:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out rs256.pem
```

A key is published under the `kid` you configure, or its RFC 7638
thumbprint. `{issuer}/jwks` answers with `Cache-Control: public,
max-age=3600`, so a resource server may hold the key set for an hour, and a
resource server refetches it when a token names a `kid` it has not seen.

## Rotating the token keys

A rotation never leaves a resource server holding a token whose key it
cannot find:

1. **Publish the next key.** Set `next_private_key_file` to the new key and
   restart. The next key is published at `{issuer}/jwks` and signs nothing.
   Wait at least an hour, the key set's cache lifetime, so every resource
   server has seen it.
2. **Make it current.** Move the new key to `private_key_file`, the old one
   to `previous_private_key_file`, remove `next_private_key_file`, and
   restart. The new key signs; the old one is still published.
3. **Retire the old key.** Keep the previous key published for the
   longest-lived token it signed plus the cache lifetime: with the
   default `access_token_lifetime` of five minutes, an hour and five
   minutes. `previous_key_overlap` removes it by itself after that long; at
   `0s` it stays until you remove `previous_private_key_file` and restart.

Every replica must run the same three files. Restart the replicas one at a
time; each one drains before it stops ([operations](operations.md)).

## The assertion keys

When FerroSMART authenticates to its identity provider with
`private_key_jwt`, the current assertion key signs a fresh assertion for
every request: `iss` and `sub` the client id, `aud` the provider's token
endpoint, a unique `jti`, `exp` 60 seconds ahead, `typ` `JWT`. The
algorithm is the one the provider's registration names (`algorithm`,
`RS256` by default), and `certificate_file` names the current key's X.509
certificate for a provider that knows the key that way.

The assertion ring rotates the same way. A provider that reads
`{issuer}/upstream-jwks`, as Keycloak does, sees the next key before it
signs. A provider that stores a certificate, as Microsoft Entra ID does,
needs the next key's certificate uploaded before step 2, and the old one
removed after step 3.
