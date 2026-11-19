- The consent page draws identity, launch and refresh scopes (`openid`,
  `fhirUser`, `profile`, `email`, `launch`, `launch/*`, `offline_access`,
  `online_access`) as fixed lines with no box, granted with the app whatever
  the form posts, so a person can no longer untick a scope the app cannot
  work without; resource and extension scopes keep their boxes. A
  `[[ferrosmart.client]]` may register `client_uri`, `logo_uri`,
  `policy_uri` and `tos_uri` (RFC 7591 §2, absolute `https` URLs), which the
  consent page links and draws, with the logo's origin admitted by the
  page's `img-src` alone. The store gains a migration (#668).
