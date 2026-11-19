- A refresh request may name a `resource` (RFC 8707 §2.2): the grant's
  own resource server or the FHIR base paired with its openEHR base, so an
  app signed in at the openEHR base gets a token for the platform's FHIR
  server on the same grant. The token's `aud` is that resource alone and
  its scope is the grant's, less the clinical scopes of the other kind;
  the scope never widens, and any other resource is `invalid_target`
  (#663).
