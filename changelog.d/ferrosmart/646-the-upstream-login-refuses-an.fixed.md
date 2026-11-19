- The upstream login refuses an ID Token without `iat` (OpenID Connect
  Core 1.0 §2), and takes one without `kid` when a single key of the
  provider's set fits its algorithm. The OpenID Foundation conformance
  suite's relying party modules `oidcc-client-test-missing-iat` and
  `oidcc-client-test-kid-absent-single-jwks` found both (#646, #648).
