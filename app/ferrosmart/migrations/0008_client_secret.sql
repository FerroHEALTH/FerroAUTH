-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- Confidential symmetric clients (SMART App Launch 2.2.0, Client
-- Authentication: Symmetric; docs/architecture.md §13.9): the Argon2id PHC
-- hash of the secret, never the secret, held by such a client alone.

ALTER TABLE client DROP CONSTRAINT client_kind_check;
ALTER TABLE client ADD CONSTRAINT client_kind_check
    CHECK (kind IN ('public', 'confidential_asymmetric', 'confidential_symmetric'));
ALTER TABLE client ADD COLUMN secret_hash text;
ALTER TABLE client ADD CONSTRAINT client_secret_check
    CHECK ((kind = 'confidential_symmetric') = (secret_hash IS NOT NULL));
ALTER TABLE client ADD CONSTRAINT client_symmetric_keys_check
    CHECK (kind <> 'confidential_symmetric' OR (jwks_uri IS NULL AND jwks IS NULL));
