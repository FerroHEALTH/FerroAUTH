- Breaking: issuers are a map by name, `[auth.issuer.<name>]`, in place of
  the `[[auth.issuer]]` array, and every other key names an issuer by its
  table's name: `described_issuer`, and a product's role lists through
  `Resolved::role_issuers` (in place of `check_role_issuers`, which took
  URLs) and `Resolved::issuer_named`. An unknown name is refused at load
  (`ConfigError::UnknownIssuer` lists the known names), a name outside the
  form (a lower-case letter, then lower-case letters, digits and `_`, at most
  64) is `ConfigError::IssuerName`, and the environment form addresses an
  issuer by name. The party, federation and attribute tables and the
  scopeless subjects sit under their issuer (`[auth.issuer.<name>.party]`,
  `.federation`, `.attributes`, `scopeless_subjects = ["sub"]`), and the
  section-level `[[auth.party]]`, `[[auth.federation]]`,
  `[[auth.attributes]]`, `scopeless_subjects` and `config::ScopelessSubject`
  are removed. Defaults derive: `AuthSection::resolve` and
  `ProductStandingSection::resolve` take the product's base URLs, the
  audience of an issuer that names none; `kind` is the preset's (`persons`
  under `ferrosmart`, `keycloak`, `entra` and `okta`, `Preset::kind`); a
  party table's `identifier_issuer` is the issuer's identifier and its
  `identifier_type` the new profile key `party_identifier_type` (`pairwise`
  under `ferrosmart`). The new profile key `patient_context` decides whether
  an issuer's `patient` claim is the launch context: on under `ferrosmart`,
  off otherwise. Under `ferrosmart` the new key `issuer_client_is_person`
  reads a token whose client is the issuer itself, FerroSMART's patient
  picker, as the person with no app grant, and its `client_id` still names
  FerroSMART. A product moves its issuer tables to named ones, refers to
  them by name, drops its own patient-issuer rule (FerroEHR's
  `patient_issuers`) and the picker's agent or self-delegate, and passes its
  base URLs to `resolve`.
