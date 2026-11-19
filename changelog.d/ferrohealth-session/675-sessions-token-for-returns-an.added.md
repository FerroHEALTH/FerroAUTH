- `Sessions::token_for` returns an access token for a second resource
  server on the session's grant: kept with the memory-store session until
  it is due, else one refresh naming the resource (RFC 8707 §2.2), with
  the rotated refresh token kept. `invalid_grant` ends the session; any
  other refusal is returned as `ForResource::Refused` and the session stays
  (#675).
