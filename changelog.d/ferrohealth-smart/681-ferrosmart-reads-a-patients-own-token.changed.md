- Breaking: the `ferrosmart` preset reads a patient's own token on a
  `persons` issuer as `CallerKind::Patient`, so `Caller::is_the_person`
  holds for it. The token must pass the client admission first (its client
  in `first_party_clients` or `delegates`, or a `Standing` answer of first
  party or delegate), carry no `act` and no representation claim, and hold
  all three: `fhirUser` is `Patient/<x>` (relative, or an absolute URL
  ending in `/Patient/<x>`), the `patient` claim is `x`, and its scopes
  carry a `patient/` grant with no `user/` or `system/` one. Any other
  FerroSMART token classifies as before, so a professional with `patient/`
  scopes stays a professional confined to the launch context. The reading
  is the new profile key `fhir_user_patient` (`Profile::fhir_user_patient`,
  `ProfileKeys::fhir_user_patient`, and the same key on `IssuerEntry`),
  which only the `ferrosmart` preset sets and an issuer table can turn off.
  A product that builds `Profile`, `ProfileKeys` or `IssuerEntry` with a
  struct literal adds the field, and a product that read a patient's own
  token through FerroSMART by its own rule (FerroEHR's `patient_issuers`)
  drops that rule and reads `Caller::is_the_person`.
