-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- A client's launch URL, normalized (RFC 3986 §6.2.2), by which an EHR's
-- launch registration may name the app (docs/architecture.md §13.17;
-- SMART App Launch 2.2.0, Task profile for requesting a SMART launch). One
-- client per launch URL.

ALTER TABLE client ADD COLUMN launch_uri text UNIQUE;
