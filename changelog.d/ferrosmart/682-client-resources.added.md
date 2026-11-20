- Breaking: `[[ferrosmart.client]]` takes `resources`, the
  `[[ferrosmart.resource]]` bases the client's tokens may name in `aud`.
  An authorization request, a client credentials request, a refresh, a code
  redemption or a launch registration naming any other base is refused
  `invalid_target` (RFC 8707 §2), and a client credentials request without
  `resource` takes the one base the client lists alone. A client that lists
  none reaches no resource server, only FerroSMART's own endpoints, so every
  client table adds the bases it is for; a base no
  `[[ferrosmart.resource]]` table configures is refused at load. The admin
  API's client document carries `resources` too, and a base taken off a
  client's list is refused from its next request.
