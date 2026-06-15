-- KernelWatch host (whole-server) monitoring: scope dimension.
--
-- Like the earlier migrations this runs on FIRST initialization of the
-- TimescaleDB volume (/docker-entrypoint-initdb.d) and is mirrored idempotently
-- by the application at startup (internal/storage/postgres.go → schemaStatements),
-- so existing volumes and the bare-binary deployment are upgraded too.
--
-- `scope` distinguishes a host-wide finding ('host') from a container one
-- ('container'). It is NOT NULL DEFAULT 'container' so every pre-existing alert
-- keeps its original meaning. Suppressions gain `scope` and `hostname` so a
-- false-positive rule can be narrowed to one scope or one host in a shared fleet
-- database (these default to '' = any).

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS scope text NOT NULL DEFAULT 'container';
CREATE INDEX IF NOT EXISTS alerts_scope_ts ON alerts (scope, timestamp DESC);

ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS scope    text NOT NULL DEFAULT '';
ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS hostname text NOT NULL DEFAULT '';
