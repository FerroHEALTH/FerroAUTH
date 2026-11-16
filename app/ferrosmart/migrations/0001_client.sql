-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1

-- The client registry (docs/architecture.md §13.9). A client registered by
-- the configuration carries source 'config' and is replaced from it at every
-- start; no specification governs the registry's storage: our own design.
CREATE TABLE client (
    client_id    text PRIMARY KEY,
    name         text NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('public', 'confidential_asymmetric')),
    jwks_uri     text,
    jwks         jsonb,
    redirect_uris text[] NOT NULL DEFAULT '{}',
    scopes       text[] NOT NULL DEFAULT '{}',
    grant_types  text[] NOT NULL DEFAULT '{}',
    source       text NOT NULL CHECK (source IN ('config')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CHECK (kind <> 'confidential_asymmetric' OR (jwks_uri IS NULL) <> (jwks IS NULL)),
    CHECK (kind <> 'public' OR (jwks_uri IS NULL AND jwks IS NULL))
);
