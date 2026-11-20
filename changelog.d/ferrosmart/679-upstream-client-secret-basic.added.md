- An upstream provider entry may authenticate with a client secret as HTTP
  Basic: `[ferrosmart.upstream.oidc.client_secret_basic]` with `secret_file`
  (or `secret`), in place of the default
  `[ferrosmart.upstream.oidc.private_key_jwt]`. Each entry names exactly one
  of the two, the secret never shows in a log or a debug rendering, and
  FerroSMART refuses to start when the provider's
  `token_endpoint_auth_methods_supported` does not list the method chosen.
