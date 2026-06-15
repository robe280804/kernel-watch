-- KernelWatch operator suppression rules (false-positive management).
--
-- Like 0001_alerts.sql, this runs on FIRST initialization of the TimescaleDB
-- volume (/docker-entrypoint-initdb.d) and is also applied idempotently by the
-- application at startup (internal/storage/postgres.go → schemaStatements), so
-- existing volumes and the bare-binary deployment are covered too.
--
-- A suppression silences an alert only when EVERY non-empty column matches it
-- (criteria are ANDed). Managed at runtime via the REST API; the detector
-- reloads the active set on a short interval.

CREATE TABLE IF NOT EXISTS suppressions (
    id             uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    rule_id        text        NOT NULL DEFAULT '',  -- detection rule id; '' = any
    container_name text        NOT NULL DEFAULT '',  -- '' = any container
    process_name   text        NOT NULL DEFAULT '',  -- '' = any process
    substr         text        NOT NULL DEFAULT '',  -- substring of name/image/cmdline/ancestry
    reason         text        NOT NULL DEFAULT '',  -- operator note
    created_by     text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now()
);
