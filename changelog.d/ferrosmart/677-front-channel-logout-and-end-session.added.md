- FerroSMART takes OpenID Connect Front-Channel Logout 1.0 at
  `{issuer}/frontchannel-logout`: a provider that offers only front-channel
  logout, such as Microsoft Entra ID, renders it in an iframe with its
  `iss` and the login's `sid`, and the sessions of that `sid` end with their
  `online_access` grants. The page is never cached and only the provider's
  origins may frame it.
- FerroSMART has an end-session endpoint (OpenID Connect RP-Initiated
  Logout 1.0), named as `end_session_endpoint` in discovery: it checks the
  `id_token_hint` it issued, the `client_id` and a `post_logout_redirect_uri`
  the client registers under the new `post_logout_redirect_uris` key, asks
  the person to confirm, ends their `online_access` grants, forwards to the
  provider's own end-session endpoint and returns the browser to the app
  with its `state`. Register `{issuer}/logout/return` at the provider as a
  post-logout redirect URI. Each logout is audited as `logged-out`, and the
  store gains a migration.
