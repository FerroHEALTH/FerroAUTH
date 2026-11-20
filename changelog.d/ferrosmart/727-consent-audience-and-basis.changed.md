- A remembered consent is bound to the resource server it was given for:
  it answers only for the same client, the same `aud` and scopes it fully
  covers. The store migration drops the consents kept under the old key,
  so each person is asked once again.
- Every `authorization-code` audit record names the basis of the code as
  its `basis` detail: `page`, `remembered`, `organisation` or
  `first-party`.
- An organisation approval may list `patient/` scopes for staff, and it
  covers them in a professional's EHR launch with no consent page
  (OpenID Connect Core 1.0 §3.1.2.4). A standalone request for `patient/`
  scopes and every patient keep the page, unless the app is first party.
