-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1

-- A login at the upstream OpenID Connect provider, which an online_access
-- grant lives no longer than (docs/architecture.md section 13.6 item 7, our
-- own design): it ends at the provider's logout or after the idle time.
CREATE TABLE upstream_session (
    id         text PRIMARY KEY,
    issuer     text NOT NULL,
    subject    text NOT NULL,
    sid        text,
    last_seen  timestamptz NOT NULL DEFAULT now(),
    ended_at   timestamptz
);
CREATE INDEX upstream_session_sid ON upstream_session (issuer, sid);
CREATE INDEX upstream_session_subject ON upstream_session (issuer, subject);

-- An authorization grant (RFC 6749 section 1.3): what a person gave a
-- client, which every access and refresh token issued under it shares, so a
-- revocation reaches all of them (RFC 7009 section 2.1) and introspection
-- answers the launch context of the token response (SMART App Launch 2.2.0,
-- Token Introspection).
CREATE TABLE authorization_grant (
    id               text PRIMARY KEY,
    client_id        text NOT NULL,
    subject          text NOT NULL,
    fhir_user        text,
    audience         text NOT NULL,
    scope            text NOT NULL,
    context          jsonb NOT NULL DEFAULT '{}',
    auth_time        bigint,
    access           text CHECK (access IN ('offline', 'online')),
    upstream_session text REFERENCES upstream_session (id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    revoked_at       timestamptz,
    CHECK (jsonb_typeof(context) = 'object')
);
CREATE INDEX authorization_grant_session ON authorization_grant (upstream_session);
CREATE INDEX authorization_grant_subject ON authorization_grant (subject, client_id);

-- A refresh token, stored as its SHA-256 (docs/architecture.md section
-- 13.9). A rotated token keeps its row with used_at set, so presenting it
-- again is detected as reuse and revokes the grant (RFC 9700 section 4.14.2).
CREATE TABLE refresh_token (
    token_hash  text PRIMARY KEY,
    grant_id    text NOT NULL REFERENCES authorization_grant (id) ON DELETE CASCADE,
    predecessor text,
    issued_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    revoked_at  timestamptz
);
CREATE INDEX refresh_token_grant ON refresh_token (grant_id);
CREATE INDEX refresh_token_expires_at ON refresh_token (expires_at);

-- The grant an access token was issued under; none for a client
-- credentials token, which has no grant to revoke with it.
ALTER TABLE access_token
    ADD COLUMN grant_id text REFERENCES authorization_grant (id) ON DELETE CASCADE;
CREATE INDEX access_token_grant ON access_token (grant_id);

-- The upstream session an authorization request logged in under, carried to
-- its code so the grant the code opens names it.
ALTER TABLE pending_authorization ADD COLUMN upstream_session text;
ALTER TABLE authorization_code ADD COLUMN upstream_session text;
