- An openEHR `[[ferrosmart.resource]]` can name the platform's FHIR server
  as its `fhir_base`, with the `subject_system` of the `Patient.identifier`
  that names the EHR's subject. At such a base the patient picker searches
  the FHIR server and looks the chosen patient's EHR up at the openEHR
  server, each as the signed-in person, so a standalone launch with
  `launch/patient` gets both `patient` and `ehrId` (SMART on openEHR draft,
  Context Selection and Service Discovery). A patient without an EHR the
  person may see is told so and enters no context (#574).
