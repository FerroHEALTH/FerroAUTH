-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1

-- An authorization request between the authorization endpoint and the
-- code: the client's validated request, the upstream login's state, nonce
-- and PKCE verifier, and, once the person logged in, who they are and the
-- scopes the consent page offers (docs/architecture.md section 13.9). The
-- id rides in the browser's cookie; no specification governs the storage.
CREATE TABLE pending_authorization (
    id                text PRIMARY KEY,
    client_id         text NOT NULL,
    redirect_uri      text NOT NULL,
    scope             text NOT NULL,
    state             text NOT NULL,
    nonce             text,
    code_challenge    text NOT NULL,
    audience          text NOT NULL,
    upstream_state    text NOT NULL UNIQUE,
    upstream_nonce    text NOT NULL,
    upstream_verifier text NOT NULL,
    form_token        text NOT NULL,
    subject           text,
    fhir_user         text,
    display_name      text,
    offered_scope     text,
    auth_time         bigint,
    expires_at        timestamptz NOT NULL
);
CREATE INDEX pending_authorization_expires_at ON pending_authorization (expires_at);

-- An authorization code, stored as its SHA-256, single use (RFC 6749
-- section 4.1.2; OAuth 2.1 draft section 4.1.3).
CREATE TABLE authorization_code (
    code_hash      text PRIMARY KEY,
    client_id      text NOT NULL,
    redirect_uri   text NOT NULL,
    code_challenge text NOT NULL,
    audience       text NOT NULL,
    subject        text NOT NULL,
    fhir_user      text,
    scope          text NOT NULL,
    nonce          text,
    auth_time      bigint NOT NULL,
    expires_at     timestamptz NOT NULL,
    redeemed_at    timestamptz
);
CREATE INDEX authorization_code_expires_at ON authorization_code (expires_at);

-- The code an access token was issued for, so a second use of the code
-- revokes it (OAuth 2.1 draft section 4.1.3).
ALTER TABLE access_token ADD COLUMN code_hash text;
CREATE INDEX access_token_code_hash ON access_token (code_hash);
