-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1

-- The IDs of the SAML assertions a login was admitted with, each by the
-- identity provider that issued it, kept until the assertion could no
-- longer be confirmed, so a replayed assertion is refused on every replica
-- (saml-profiles-2.0-os section 4.1.4.5).
CREATE TABLE seen_saml_assertion (
    identity_provider text NOT NULL,
    assertion_id      text NOT NULL,
    expires_at        timestamptz NOT NULL,
    PRIMARY KEY (identity_provider, assertion_id)
);
CREATE INDEX seen_saml_assertion_expires_at ON seen_saml_assertion (expires_at);
