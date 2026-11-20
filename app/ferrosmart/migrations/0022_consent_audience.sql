-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- A remembered consent is bound to the resource server it was given for, so
-- a decision about what an app may read at one server never answers for
-- another. No specification governs this: our own design. No deployment is
-- in production, so the consents kept under the old key are dropped and
-- their people asked again.

DELETE FROM consent;
ALTER TABLE consent ADD COLUMN audience text NOT NULL;
ALTER TABLE consent DROP CONSTRAINT consent_pkey;
ALTER TABLE consent ADD PRIMARY KEY (subject, client_id, audience);
