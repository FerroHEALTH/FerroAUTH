- The profile key `audience_delegates`: on a `persons` issuer under the
  `ferrosmart` preset, every client of a token whose `aud` names this
  resource server is a delegate, beside the clients `delegates` lists, so an
  app registered at FerroSMART with this product among its `resources`
  needs no entry here. It is refused under any other preset
  (`ProfileError::AudienceDelegates`), on another issuer kind, and beside a
  product's standing (`ProductStandingSection` does not know the key).
  `Profile` and `ProfileKeys` gain the field.
