-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- Several upstream providers: the providers a client's people may log in
-- at (every one when empty), and the provider each pending login and
-- logout went to. No specification governs the storage: our own design.

ALTER TABLE client
    ADD COLUMN upstreams text[] NOT NULL DEFAULT '{}';

ALTER TABLE pending_authorization
    ADD COLUMN upstream_provider text;

ALTER TABLE pending_logout
    ADD COLUMN upstream_provider text;
