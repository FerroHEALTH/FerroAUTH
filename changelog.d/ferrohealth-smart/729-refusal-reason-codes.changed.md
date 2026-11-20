- Breaking: every refusal carries a stable reason code (`audience-mismatch`,
  `issuer-unknown`, `delegate-not-granted`, `refused-unbound` and the rest
  the book lists). The gate logs each refusal at info with the code, the
  token's issuer, client id and key id, never the token or a claim that
  names a person, and `Denied::challenge` sends the code as the
  `error_description` of the `401` or `403` (RFC 6750 §3); a missing
  credential and a Basic challenge carry none. `guard::Render::render` and
  `extract::HeaderOnly::respond` take a `refusal::Denied` in place of a
  `Refusal`, `Reason::as_str` returns the code, `Reason::Unclassified`
  carries the step's code (`kind::Unclassified::code`), and `Reason` gains
  `BasicIncomplete`, `ScopeNotGranted`, `RouteUnclassified`,
  `PartySourceUnavailable` and `Party`, the code a product refuses a party
  binding with (`party::Outcome::refusal_reason`). A product renders with
  `denied.challenge(realm)` and `denied.refusal().status()`, and refuses
  an unbound login with `Denied::new(Refusal::Forbidden,
  outcome.refusal_reason())`.
