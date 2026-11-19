- An authorization request without `aud` (or `resource`) defaults to the
  resource server when the deployment configures exactly one, as the token
  endpoint already defaults `resource`; with two or more it is still refused,
  and a wrong `aud` is refused either way. Apps should still send `aud`, as
  SMART App Launch 2.2.0 requires (#670).
