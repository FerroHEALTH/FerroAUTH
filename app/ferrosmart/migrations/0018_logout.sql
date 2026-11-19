-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- RP-Initiated Logout 1.0: the post-logout redirect URIs a client registers
-- (section 3.1) and the logout a person is asked to confirm (section 2),
-- kept until the browser comes back from the upstream provider's own
-- end-session endpoint.

ALTER TABLE client
    ADD COLUMN post_logout_redirect_uris text[] NOT NULL DEFAULT '{}';

CREATE TABLE pending_logout (
    id             text PRIMARY KEY,
    client_id      text,
    subject        text,
    redirect_uri   text,
    state          text,
    form_token     text NOT NULL,
    upstream_state text NOT NULL,
    expires_at     timestamptz NOT NULL
);

CREATE INDEX pending_logout_upstream_state ON pending_logout (upstream_state);
