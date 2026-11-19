- Breaking: requires `ferrohealth-smart` 0.31 in place of 0.30. Its
  `ferrosmart` preset reads a patient's own token as `CallerKind::Patient`,
  and `Profile`, `ProfileKeys` and `IssuerEntry` gain
  `fhir_user_patient`.
