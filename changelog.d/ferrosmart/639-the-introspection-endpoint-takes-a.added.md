- The introspection endpoint takes a confidential symmetric client's
  secret, by HTTP Basic or in the form, as the token endpoint does (RFC
  7662 §2.1, RFC 6749 §2.3.1), so a gateway that introspects with
  `client_secret_basic`, such as Apache APISIX, can sit in front of a
  resource server. The client's ceiling lists `system/introspect`; a wrong
  secret answers `401` `invalid_client` and a client without the scope
  `401` `unauthorized_client`, each challenged `Basic`. The metadata's
  `introspection_endpoint_auth_methods_supported` lists
  `client_secret_basic` and `client_secret_post` beside `private_key_jwt`
  (#639).
