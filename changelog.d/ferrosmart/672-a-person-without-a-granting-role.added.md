- When no requested scope can be granted to the person, FerroSMART shows a
  page that names the configured roles that would grant one (or says the
  app asks for access the server does not give it), and its button returns
  to the app with `access_denied`, the `state` and the `iss`, in place of
  sending `invalid_scope` back at once. The refusal is written as an
  `authorization.refused` audit line.
