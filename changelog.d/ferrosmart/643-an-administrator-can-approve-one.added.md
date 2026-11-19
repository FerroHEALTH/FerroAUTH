- An administrator can approve one of the organisation's own apps for its
  staff with `[ferrosmart.client.organisation_approval]` (scopes, who,
  when), so a professional who opens it sees no consent page (SMART App
  Launch 2.2.0, Obtain authorization code, Response). Only `user/` scopes
  with their launch, OpenID, refresh and extension scopes can be approved;
  a request with a `patient/` scope, a patient's own login and a request
  beyond the approval show the page. The granted scope never exceeds the
  person's roles. Each skipped page is audited with the approval as its
  basis, the management page lists the app as approved by the
  organisation, and clearing the approval revokes every token issued on it
  at the next start (#643).
