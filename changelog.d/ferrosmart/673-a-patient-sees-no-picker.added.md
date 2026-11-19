- A patient whose `fhirUser` names their own `Patient` at the requested
  FHIR server, absolute or relative to its base, or at the FHIR server
  paired with the requested openEHR server, sees no patient picker: their
  record, read again as them, is the launch context, with their EHR at a
  paired base, and a record that cannot be read is a page that says so.
  They are offered the client's `patient/` scopes without a role. A
  professional still picks. `consent::offer` takes a `FhirUser` in place of
  the `has_fhir_user` flag.
