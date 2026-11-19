-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- What a client registers about its app for the consent page (RFC 7591
-- section 2, client metadata): its home page, logo, privacy policy and terms
-- of service, each an absolute https URL or null.

ALTER TABLE client
    ADD COLUMN client_uri text,
    ADD COLUMN logo_uri text,
    ADD COLUMN policy_uri text,
    ADD COLUMN tos_uri text;
