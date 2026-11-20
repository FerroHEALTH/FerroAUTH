- Breaking: the `protocol` key of `[[ferrosmart.upstream]]` is removed, and
  the table present names the protocol: `[ferrosmart.upstream.oidc]` for
  OpenID Connect or `[ferrosmart.upstream.saml]` for SAML 2.0, exactly one
  per entry. A configuration that still sets `protocol` is refused as an
  unknown key; delete the line (and `FERROSMART__…__PROTOCOL` from the
  environment). `private_key_jwt` is taken when an entry names no client
  authentication table, so the empty
  `[ferrosmart.upstream.oidc.private_key_jwt]` header goes too and
  `[ferrosmart.upstream.oidc.private_key_jwt.keys]` alone is enough; an
  entry without the assertion key is refused for that missing key.
