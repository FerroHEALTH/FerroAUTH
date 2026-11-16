-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1

-- A consent the person chose to remember: the scopes they gave a client,
-- until they revoke it at the management page (docs/architecture.md section
-- 13.6 item 6; SMART App Launch 2.2.0, Conformance, management_endpoint).
CREATE TABLE consent (
    subject    text NOT NULL,
    client_id  text NOT NULL,
    scope      text NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (subject, client_id)
);

-- A management visit has no client: the person logs in to see and revoke
-- what they remembered.
ALTER TABLE pending_authorization ALTER COLUMN client_id DROP NOT NULL;
ALTER TABLE pending_authorization ADD COLUMN purpose text NOT NULL DEFAULT 'authorize'
    CHECK (purpose IN ('authorize', 'manage'));
