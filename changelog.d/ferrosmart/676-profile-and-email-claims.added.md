- The `profile` and `email` scopes are offered within a client's ceiling,
  listed in `scopes_supported`, and, when granted, pass the upstream ID
  Token's `name` and `preferred_username` (`profile`) and `email` and
  `email_verified` (`email`) into FerroSMART's ID Token, never into an
  access token (OpenID Connect Core 1.0 §5.4). `claims_supported` lists the
  four. The store gains a migration.
