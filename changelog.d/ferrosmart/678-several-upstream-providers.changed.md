- FerroSMART logs people in at several identity providers. `[ferrosmart.upstream]`
  becomes `[[ferrosmart.upstream]]`, one entry per provider with a `name`,
  an optional `label` and `protocol = "oidc"`, whose OpenID Connect keys
  (`issuer`, `client_id`, `scopes`, `fhir_user_claim`, `role_claims`,
  `trusted_audiences` and the `private_key_jwt` table) move into
  `[ferrosmart.upstream.oidc]`; an environment override is now
  `FERROSMART__FERROSMART__UPSTREAM__0__OIDC__ISSUER` and a `--set` is
  `ferrosmart.upstream.0.oidc.issuer`. A `[[ferrosmart.client]]` names its
  providers in `upstreams` (every provider when it names none): one sends
  the browser straight there, several show a chooser at `{issuer}/login`.
  Several Microsoft Entra ID tenants are several entries. Back-channel and
  front-channel logouts are matched to their provider by `iss`, and
  `{issuer}/upstream-jwks` publishes every provider's assertion keys. The
  store gains a migration.
