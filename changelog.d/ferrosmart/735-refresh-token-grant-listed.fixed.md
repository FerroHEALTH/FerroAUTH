- The RFC 8414 and OpenID Connect metadata list `refresh_token` in
  `grant_types_supported`, since the token endpoint serves that grant (RFC
  8414 §2). The token endpoint refuses every grant its metadata leaves out
  as `unsupported_grant_type`, so without a login the authorization code
  grant is refused.
