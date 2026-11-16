-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1

-- The assertion ids already seen, kept until the assertion expires, so a
-- replayed client assertion is refused on every replica (SMART App Launch
-- 2.2.0, Client Authentication: Asymmetric, Signature Verification).
CREATE TABLE seen_jti (
    issuer     text NOT NULL,
    jti        text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (issuer, jti)
);

-- Every access token issued, by its jti, so introspection and revocation
-- answer for a self-contained JWT (docs/architecture.md section 13.9).
CREATE TABLE access_token (
    jti        text PRIMARY KEY,
    client_id  text NOT NULL,
    subject    text NOT NULL,
    audience   text NOT NULL,
    scope      text NOT NULL,
    issued_at  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX access_token_expires_at ON access_token (expires_at);
CREATE INDEX seen_jti_expires_at ON seen_jti (expires_at);
