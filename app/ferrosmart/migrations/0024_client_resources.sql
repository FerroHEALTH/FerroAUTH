-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The resource servers a client's tokens may name in `aud`
-- (docs/architecture.md §13.6 item 12): a request for any other base is
-- refused `invalid_target` (RFC 8707 §2), so a token's audience says the
-- client was admitted for that server. No deployment is in production, so
-- every client starts with none and is registered again with its list.

ALTER TABLE client ADD COLUMN resources text[] NOT NULL DEFAULT '{}';
