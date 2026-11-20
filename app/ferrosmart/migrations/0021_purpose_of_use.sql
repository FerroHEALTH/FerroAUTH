-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The purpose of use a professional chose on the patient picker of an
-- openEHR base, kept from the lookup to the look-up-again of the choice so
-- the two declare the same one. No specification governs the storage: our
-- own design.

ALTER TABLE pending_authorization
    ADD COLUMN purpose_of_use text;
