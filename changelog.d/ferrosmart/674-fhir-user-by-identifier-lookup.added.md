- When the identity provider sends no `fhirUser` claim, FerroSMART can
  find the person by an identifier: each
  `[[ferrosmart.resource.fhir_user_lookup]]` of a FHIR base names a
  `resource_type`, the upstream `claim` holding the identifier's value and
  the identifier's `system`, and FerroSMART searches
  `[base]/[type]?identifier=[system]|[value]` as the person. One match is
  the `fhirUser`; none, several or a refused search leave it out, the
  consent page says so, and a `fhir_user.lookup` audit line records the
  outcome without a value. A lookup on the FHIR base paired with an openEHR
  base serves that base too.
