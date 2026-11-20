- A person can log in at a SAML 2.0 identity provider: a `protocol =
  "saml"` entry in `[[ferrosmart.upstream]]` with its
  `[ferrosmart.upstream.saml]` table, and FerroSMART as one service
  provider in `[ferrosmart.saml]`, its metadata at
  `{issuer}/saml/metadata`. The assertion consumer service
  `{issuer}/saml/acs` takes a response by HTTP-POST or an artifact,
  resolved over mutual TLS; the provider's metadata is read again on a
  timer; each assertion is admitted once, on every replica; the classes
  at or above the provider's minimum assurance are asked for and any
  other is refused; the `claims` table maps attributes to the claims of
  `fhirUser`, the roles and the `fhirUser` lookup; and every outcome is a
  `110122` Login record naming the check that failed. The chooser lists a
  SAML provider beside an OpenID Connect one. An entry without
  `[ferrosmart.saml]` or with an incomplete table is refused at load.
