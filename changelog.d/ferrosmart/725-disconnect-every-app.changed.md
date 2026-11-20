- The management page lists every app holding live access to the person's
  data, organisation-approved and first-party apps included, each with a
  Disconnect button. Disconnect forgets the person's remembered consent and
  revokes the app's grants, refresh tokens and access tokens about them at
  once, and leaves the organisation approval standing; the
  `consent-withdrawn` record names the grants revoked (SMART App Launch
  2.2.0, `offline_access` and `management_endpoint`).
