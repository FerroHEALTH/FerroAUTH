-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The admin API over the client registry (docs/architecture.md §13.8,
-- §13.9). A client the API created or changed carries source 'admin', and
-- the configuration no longer writes it at start; a disabled client keeps
-- its row with the time it was disabled, and no request finds it. No
-- specification governs the registry's storage: our own design.

ALTER TABLE client DROP CONSTRAINT client_source_check;
ALTER TABLE client ADD CONSTRAINT client_source_check
    CHECK (source IN ('config', 'admin'));
ALTER TABLE client ADD COLUMN disabled_at timestamptz;

CREATE INDEX access_token_client ON access_token (client_id) WHERE revoked_at IS NULL;
CREATE INDEX authorization_grant_client ON authorization_grant (client_id) WHERE revoked_at IS NULL;
