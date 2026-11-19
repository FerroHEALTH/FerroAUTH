- A `[[ferrosmart.role]]` may grant extension scopes, those that start with
  two underscores (SMART App Launch 2.2.0, Scopes and Launch Context,
  Extensibility), such as FerroEHR's `__ferroehr.platform`. A person is
  granted one when the request asks for it, the client's ceiling lists it
  and one of their roles grants it; the consent page names it in plain
  words, and `scopes_supported` lists every extension scope a role grants.
  Any other scope outside the SMART set is still never granted to a person
  (#647).
