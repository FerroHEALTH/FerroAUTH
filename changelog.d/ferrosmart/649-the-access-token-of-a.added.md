- The access token of a user flow carries the person's roles in a `roles`
  claim (RFC 9068 §2.2.3.1): the roles the identity provider's
  `role_claims` carry that a `[[ferrosmart.role]]` names, fixed at login
  and kept through every refresh. The introspection response carries them
  too. A Backend Services token carries none (#649).
