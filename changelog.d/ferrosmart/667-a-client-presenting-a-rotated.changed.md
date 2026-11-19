- A client presenting a rotated refresh token again within 10 seconds of
  its rotation, while the new refresh token is neither used nor revoked,
  gets that same new refresh token and a fresh access token instead of
  having the grant revoked, so a retry after a lost response or two
  requests racing (two tabs, two backend instances, two replicas) keep the
  grant. A repeat after the window, by another client, or once the new
  token was used still revokes the grant (RFC 9700 §2.2.2, §4.14.2; the
  window is FerroSMART's own design). Each repeat is recorded as
  `refresh-repeated`. The store gains a migration (#667).
