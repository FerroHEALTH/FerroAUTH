-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- An administrator's approval of a client for the whole organisation
-- (docs/architecture.md §13.6 item 6; SMART App Launch 2.2.0, Obtain
-- authorization code, Response: the server "will enforce access rules based
-- on local policies and optionally direct end-user input"): the approved
-- scope set, who approved it and when. A code and a grant issued on the
-- approval carry its time, so withdrawing the approval revokes them.

ALTER TABLE client ADD COLUMN approved_scope text[];
ALTER TABLE client ADD COLUMN approved_by text;
ALTER TABLE client ADD COLUMN approved_at timestamptz;
ALTER TABLE client ADD CONSTRAINT client_approval_check
    CHECK ((approved_scope IS NULL) = (approved_by IS NULL)
       AND (approved_by IS NULL) = (approved_at IS NULL));

ALTER TABLE authorization_code ADD COLUMN approved_at timestamptz;
ALTER TABLE authorization_grant ADD COLUMN approved_at timestamptz;
CREATE INDEX authorization_grant_approval ON authorization_grant (client_id, approved_at)
    WHERE approved_at IS NOT NULL;
