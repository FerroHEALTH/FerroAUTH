- An OpenID Connect `[[ferrosmart.upstream]]` entry may name
  `preset = "keycloak"`, `"entra"`, `"okta"` or `"zitadel"`: the scopes,
  the `fhirUser` and role claims and the assertion algorithm of
  FerroSMART's tested setup with that provider, read from a data file
  under `app/ferrosmart/presets/` with the vendor's documentation cited
  beside each value. A key the entry's `[ferrosmart.upstream.oidc]` table
  sets wins over the preset, and the examples for the four providers use
  them.
- `ferrosmart subject --upstream <name> --sub <sub>` prints the
  FerroSMART `sub` of a person from their subject at that provider, the
  pairwise identifier a resource server binds them by
  (`docs/architecture.md` §13.6 item 9), and the management page shows the
  signed-in person their own.
- `ferrosmart upstream registration <name>` prints what the provider must
  be configured with: the redirect and logout URIs, the client
  authentication with its JWK Set URL or certificate, PKCE `S256`, the
  scopes, the claims and the roles, or for SAML 2.0 the entity IDs, the
  assertion consumer service and the attributes. Both commands read the
  configuration alone, with no key, secret or database.
