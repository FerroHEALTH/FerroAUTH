-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1

-- The User Access Brands Bundle's last change (SMART App Launch 2.2.0, User
-- Access Brands, Conformance Overview: Bundle.timestamp is "the timestamp of
-- the last change to the contents"): one row, the digest of the contents a
-- replica last started with and when they became so. No specification
-- governs the storage: our own design.
CREATE TABLE brand_bundle (
    singleton  boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    digest     text NOT NULL,
    changed_at timestamptz NOT NULL
);
