-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1

-- A launch an EHR registered at POST /launch, stored as the SHA-256 of the
-- opaque value the EHR hands the app, single use, bound to the EHR that
-- registered it, the app it launches and the resource server, and holding
-- the launch context (docs/architecture.md section 13.6 item 3, 13.9). SMART
-- defines no such registration: our own design.
CREATE TABLE launch (
    launch_hash    text PRIMARY KEY,
    ehr_client_id  text NOT NULL,
    client_id      text NOT NULL,
    audience       text NOT NULL,
    context        jsonb NOT NULL,
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz
);
CREATE INDEX launch_expires_at ON launch (expires_at);
