- A client's ceiling and a role's scopes admit a requested `patient/`,
  `user/` or `system/` scope whose permission letters are a subset of a
  listed scope's, in the same context, on the same resource or under the
  wildcard `*`, and with the same query parameters, or any when the listed
  scope names none (SMART App Launch 2.2.0, SMART v2 scopes). A ceiling of
  `patient/Composition.crs` admits `patient/Composition.rs` and `.r`, so a
  deployment lists each resource once. A query-restricted ceiling still
  never admits the unrestricted scope.
