-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- What an app's authorization request asks of the person's login under
-- OpenID Connect Core 1.0 section 3.1.2.1, which the callback and the
-- consent page read (docs/architecture.md section 13.25): the prompt
-- values the upstream login carries, the max_age, the ui_locales, and
-- whether the upstream login was begun again because its authentication
-- was older than max_age.

ALTER TABLE pending_authorization ADD COLUMN prompt text NOT NULL DEFAULT '';
ALTER TABLE pending_authorization ADD COLUMN max_age bigint CHECK (max_age >= 0);
ALTER TABLE pending_authorization ADD COLUMN ui_locales text;
ALTER TABLE pending_authorization ADD COLUMN reauthenticated boolean NOT NULL DEFAULT false;
