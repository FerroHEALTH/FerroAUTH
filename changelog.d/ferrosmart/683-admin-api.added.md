- The admin API: `GET` and `POST /admin/clients`, `GET` and
  `PUT /admin/clients/{client_id}`, `POST .../disable`, `POST .../enable`
  and `DELETE .../organisation_approval` change the client registry while
  FerroSMART runs, and `GET /admin/keys` lists the signing keys with their
  states. Each request needs an access token FerroSMART issued for its own
  issuer with the new `system/admin` scope, confirmed against the store on
  every request, and each change commits with its audit record
  (`client-created`, `client-updated`, `client-disabled`,
  `client-enabled`). Withdrawing an organisation approval or disabling a
  client revokes its grants, refresh tokens and access tokens at once, at
  every replica, with no restart.
