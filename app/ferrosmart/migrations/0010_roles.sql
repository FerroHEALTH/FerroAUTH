-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The roles of the person a login maps from the upstream identity provider
-- (docs/architecture.md §13.6 item 5), carried from the login through the
-- code to the grant, so every access token issued under the grant carries
-- them in its `roles` claim (RFC 9068 §2.2.3.1).

ALTER TABLE pending_authorization ADD COLUMN roles text[] NOT NULL DEFAULT '{}';
ALTER TABLE authorization_code ADD COLUMN roles text[] NOT NULL DEFAULT '{}';
ALTER TABLE authorization_grant ADD COLUMN roles text[] NOT NULL DEFAULT '{}';
