- An administrator can mark an approved app as the organisation's own with
  `first_party = true` on its `[ferrosmart.client.organisation_approval]`.
  Its approval may then list `patient/` scopes, and a patient, related
  person or person who logs in to it sees no consent page while the
  approval covers every scope offered. An app without the mark keeps the
  page for every patient. Each skipped page is audited as
  `consent-first-party-approved`, the management page lists the app as the
  organisation's own, and setting or clearing the mark withdraws the old
  approval with every token issued on it (#666).
