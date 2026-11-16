-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1

-- FerroSMART's own audit records (docs/architecture.md section 13.2): each a
-- FHIR R4 AuditEvent, written in the transaction of the action it records,
-- kept here and read back by subject and time. The rows are never updated
-- beyond their two delivery stamps: delivered_at once the Audit Record
-- Repository took the record over the ITI-20 ATX: FHIR Feed, refused_at once
-- it refused it, which keeps the record for an operator. No specification
-- governs the table: our own design.
CREATE TABLE audit_record (
    seq          bigserial PRIMARY KEY,
    recorded_at  timestamptz NOT NULL,
    kind         text NOT NULL,
    outcome      text NOT NULL,
    subject      text,
    client_id    text,
    document     jsonb NOT NULL,
    delivered_at timestamptz,
    refused_at   timestamptz
);
CREATE INDEX audit_record_subject ON audit_record (subject, recorded_at);
CREATE INDEX audit_record_recorded_at ON audit_record (recorded_at);
CREATE INDEX audit_record_waiting ON audit_record (seq)
    WHERE delivered_at IS NULL AND refused_at IS NULL;
