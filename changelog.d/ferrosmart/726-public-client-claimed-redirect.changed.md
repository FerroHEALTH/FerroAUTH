- A public client gets an authorization code with no consent page, on an
  organisation approval or a remembered consent, only when the request's
  redirect URI is a claimed `https` URI. A custom-scheme or loopback
  redirect shows the page, with a remembered choice ticked, and
  `ferrosmart config check` warns of a first-party public client with no
  claimed `https` redirect (RFC 8252 §8.6, §7.2; RFC 6749 §10.2).
  Confidential clients are unchanged.
