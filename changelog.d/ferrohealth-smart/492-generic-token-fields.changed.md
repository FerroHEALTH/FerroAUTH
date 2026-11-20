- Breaking: no federation field names a country. `federation::Field` loses
  `NlProfessionalNumber`, `NlRole`, `NlUra` and `NlOrganisationType`
  (`nl.professional_number`, `nl.role`, `nl.ura`, `nl.organisation_type`);
  their values arrive through the generic `professional.hp_identifier`,
  `professional.hp_professional_role`, `provider.healthcare_provider_identifier`
  and `provider.facility_type`, each with its code system. The new source
  `{ constant = "…", system = "…" }` (`Source::Coded`) configures a coded
  value with its system, and a value that arrives without a code system is
  kept unsystemed (`Code::system` `None`), so a consumer can refuse to match
  it. A deployment that read the `nl.*` fields reads the generic ones by
  their code systems; the book's Annex B example profile does.
