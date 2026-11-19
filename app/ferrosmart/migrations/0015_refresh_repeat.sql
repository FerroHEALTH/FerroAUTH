-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1

-- The salt a rotated refresh token's successor was derived with, so the
-- same client presenting the rotated token again within the repeat window
-- is answered with the same successor (docs/architecture.md section 13.6
-- item 11, our own design). The successor itself is stored only as its
-- SHA-256, and only a holder of the rotated token can derive it again.
ALTER TABLE refresh_token ADD COLUMN successor_salt text;
