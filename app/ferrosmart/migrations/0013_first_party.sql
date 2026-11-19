-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The first-party mark of a client's organisation approval
-- (docs/architecture.md §13.6 item 6): the organisation's own app, whose
-- approval may cover `patient/` scopes and a patient's own login. It is
-- set and cleared with the approval, so its approver and time are the
-- approval's, and a changed mark is a new approval.

ALTER TABLE client ADD COLUMN first_party boolean NOT NULL DEFAULT false;
ALTER TABLE client ADD CONSTRAINT client_first_party_check
    CHECK (NOT first_party OR approved_at IS NOT NULL);
