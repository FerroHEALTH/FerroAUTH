-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1

-- The last change to the User Access Brands Bundle and to each of its
-- resources (SMART App Launch 2.2.0, User Access Brands, Conformance
-- Overview: Bundle.timestamp is "the timestamp of the last change to the
-- contents", and Bundle.entry.resource.meta.lastUpdated the more detailed
-- one "if the system tracks updates per Resource"): one row for the contents
-- as a whole, `Bundle`, and one per resource by its `Type/id`, each the
-- digest a replica last started with and when it became so. No
-- specification governs the storage: our own design.
CREATE TABLE brand_bundle (
    resource   text PRIMARY KEY,
    digest     text NOT NULL,
    changed_at timestamptz NOT NULL
);
