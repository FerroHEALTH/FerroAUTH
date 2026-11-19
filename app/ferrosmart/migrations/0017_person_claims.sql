-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The upstream ID Token's name, preferred_username, email and
-- email_verified, carried from the login to the code so the ID Token passes
-- them on when the profile or email scope is granted (OpenID Connect Core
-- 1.0 section 5.4; docs/architecture.md section 13.6 item 9).

ALTER TABLE pending_authorization ADD COLUMN person_claims jsonb;
ALTER TABLE authorization_code ADD COLUMN person_claims jsonb;
