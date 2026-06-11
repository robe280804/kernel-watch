-- KernelWatch alert storage schema.
--
-- This file runs automatically on FIRST initialization of the TimescaleDB
-- volume (mounted at /docker-entrypoint-initdb.d in docker-compose.yml). The
-- application also applies the same DDL idempotently at startup
-- (internal/storage/postgres.go → schemaStatements), so existing volumes and
-- the bare-binary deployment are covered too. Everything here is IF NOT EXISTS.

CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS alerts (
    id             uuid        NOT NULL DEFAULT gen_random_uuid(),
    timestamp      timestamptz NOT NULL,
    server_name    text,
    rule_id        text,
    severity       text,
    container_id   text,
    container_name text,
    image_name     text,
    syscall        text,
    pid            bigint,
    process_name   text,
    parent_name    text,
    ancestry       text[],
    cmdline        text,
    reason         text,
    mitre_ttp      text,
    mitre_tactic   text,
    tags           text[],
    details        jsonb,
    PRIMARY KEY (id, timestamp)  -- hypertables require the partition column in any unique index
);

SELECT create_hypertable('alerts', 'timestamp', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS alerts_container_ts ON alerts (container_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS alerts_severity_ts  ON alerts (severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS alerts_rule_ts      ON alerts (rule_id, timestamp DESC);

-- Retention: drop alert chunks older than 90 days. Adjust/remove to taste; the
-- application re-applies this from KW_DB_RETENTION_DAYS at startup.
SELECT add_retention_policy('alerts', INTERVAL '90 days', if_not_exists => TRUE);
