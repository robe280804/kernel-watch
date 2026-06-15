// Package storage persists KernelWatch alerts to TimescaleDB.
//
// The store is deliberately best-effort and non-fatal: a security monitor must
// keep running even if its database is unavailable. Alerts are pushed onto a
// bounded buffer and flushed in batches by a background worker; if the DB is
// down the worker retries, and if the buffer fills, alerts are dropped (counted)
// rather than blocking the event loop. The on-disk log file remains the durable
// fallback.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/config"
)

const (
	bufferSize    = 2000
	batchSize     = 100
	flushInterval = 2 * time.Second
)

// row is the flattened representation inserted into the alerts table.
type row struct {
	Timestamp                                                          time.Time
	ServerName, RuleID, Severity, Scope                                string
	ContainerID, ContainerName, ImageName                             string
	Syscall                                                            string
	PID                                                                int64
	ProcessName, ParentName                                            string
	Ancestry                                                           []string
	CmdLine, Reason, MitreTTP, MitreTactic                             string
	Tags                                                               []string
	Details                                                            []byte // jsonb (nil = NULL)
}

func toRow(a *alerter.Alert) row {
	var details []byte
	if len(a.Details) > 0 {
		details, _ = json.Marshal(a.Details)
	}
	scope := a.Scope
	if scope == "" {
		scope = alerter.ScopeContainer // backfill default for pre-host-monitoring alerts
	}
	return row{
		Timestamp:     a.Timestamp,
		ServerName:    a.ServerName,
		RuleID:        a.RuleID,
		Severity:      string(a.Severity),
		Scope:         scope,
		ContainerID:   a.ContainerID,
		ContainerName: a.ContainerName,
		ImageName:     a.ImageName,
		Syscall:       a.Syscall,
		PID:           int64(a.PID),
		ProcessName:   a.ProcessName,
		ParentName:    a.ParentName,
		Ancestry:      a.Ancestry,
		CmdLine:       a.CmdLine,
		Reason:        a.Reason,
		MitreTTP:      a.MITRETTP,
		MitreTactic:   a.MITRETactic,
		Tags:          a.Tags,
		Details:       details,
	}
}

// inserter abstracts the database so the buffering/batching logic in Store is
// unit-testable without a real Postgres (see postgres_test.go).
type inserter interface {
	ensureSchema(ctx context.Context) error
	insertBatch(ctx context.Context, rows []row) error
	close()
}

// Store is an async, resilient alert sink. It satisfies alerter.AlertSink.
type Store struct {
	in      inserter
	q       querier // read path (alert queries, stats, suppressions); nil in unit tests
	ch      chan row
	done    chan struct{}
	wg      sync.WaitGroup
	dropped atomic.Uint64
}

// New builds a TimescaleDB-backed Store from config and starts its worker. It
// never blocks on or fails because of a down database.
func New(cfg *config.Config) *Store {
	pg := newPgInserter(cfg.DSN(), cfg.DBRetentionDays)
	s := newStore(pg)
	s.q = pg // same connection pool serves the read path (API queries)
	return s
}

func newStore(in inserter) *Store {
	s := &Store{
		in:   in,
		ch:   make(chan row, bufferSize),
		done: make(chan struct{}),
	}
	s.wg.Add(1)
	go s.worker()
	return s
}

// Save queues an alert for persistence. Non-blocking: if the buffer is full the
// alert is dropped and counted.
func (s *Store) Save(a *alerter.Alert) {
	if s == nil {
		return
	}
	select {
	case s.ch <- toRow(a):
	default:
		if n := s.dropped.Add(1); n%100 == 1 {
			slog.Warn("alert storage buffer full, dropping alerts", "dropped_total", n)
		}
	}
}

// Close stops intake, flushes the buffer (bounded by a timeout), and closes the
// pool.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	close(s.done)
	finished := make(chan struct{})
	go func() { s.wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		slog.Warn("alert storage: close timed out before flush completed")
	}
	s.in.close()
	if d := s.dropped.Load(); d > 0 {
		slog.Warn("alert storage: alerts dropped during run", "total", d)
	}
	return nil
}

func (s *Store) worker() {
	defer s.wg.Done()
	ctx := context.Background()

	// Ensure the schema, retrying until the DB is ready (or we're shutting down).
	for {
		if err := s.in.ensureSchema(ctx); err != nil {
			slog.Warn("alert storage: database not ready, retrying", "err", err)
			select {
			case <-time.After(5 * time.Second):
				continue
			case <-s.done:
				return
			}
		}
		break
	}
	slog.Info("alert storage ready")

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	batch := make([]row, 0, batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.insertWithRetry(ctx, batch); err != nil {
			slog.Error("alert storage: insert failed after retries, dropping batch", "rows", len(batch), "err", err)
			s.dropped.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case r := <-s.ch:
			batch = append(batch, r)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.done:
			// Drain whatever is buffered, then exit.
			for {
				select {
				case r := <-s.ch:
					batch = append(batch, r)
					if len(batch) >= batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *Store) insertWithRetry(ctx context.Context, rows []row) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = s.in.insertBatch(cctx, rows)
		cancel()
		if err == nil {
			return nil
		}
		time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
	}
	return err
}

// ── Postgres-backed inserter ─────────────────────────────────────────────────

type pgInserter struct {
	dsn           string
	retentionDays int

	mu   sync.Mutex
	pool *pgxpool.Pool
}

func newPgInserter(dsn string, retentionDays int) *pgInserter {
	return &pgInserter{dsn: dsn, retentionDays: retentionDays}
}

// getPool lazily creates the connection pool (creation does not require the
// server to be reachable).
func (p *pgInserter) getPool(ctx context.Context) (*pgxpool.Pool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pool != nil {
		return p.pool, nil
	}
	pool, err := pgxpool.New(ctx, p.dsn)
	if err != nil {
		return nil, err
	}
	p.pool = pool
	return pool, nil
}

func (p *pgInserter) ensureSchema(ctx context.Context) error {
	pool, err := p.getPool(ctx)
	if err != nil {
		return err
	}
	if err := pool.Ping(ctx); err != nil {
		return err
	}
	for _, stmt := range schemaStatements(p.retentionDays) {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("schema: %w", err)
		}
	}
	return nil
}

const insertSQL = `INSERT INTO alerts
(timestamp, server_name, rule_id, severity, scope, container_id, container_name, image_name,
 syscall, pid, process_name, parent_name, ancestry, cmdline, reason, mitre_ttp,
 mitre_tactic, tags, details)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`

func (p *pgInserter) insertBatch(ctx context.Context, rows []row) error {
	pool, err := p.getPool(ctx)
	if err != nil {
		return err
	}
	batch := &pgx.Batch{}
	for _, r := range rows {
		batch.Queue(insertSQL,
			r.Timestamp, r.ServerName, r.RuleID, r.Severity, r.Scope, r.ContainerID, r.ContainerName,
			r.ImageName, r.Syscall, r.PID, r.ProcessName, r.ParentName, r.Ancestry, r.CmdLine,
			r.Reason, r.MitreTTP, r.MitreTactic, r.Tags, r.Details)
	}
	br := pool.SendBatch(ctx, batch)
	defer br.Close()
	for range rows {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

func (p *pgInserter) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pool != nil {
		p.pool.Close()
	}
}

// schemaStatements returns the idempotent DDL that creates the alerts hypertable.
// Mirrored by migrations/0001_alerts.sql for fresh docker-entrypoint-initdb.d runs.
func schemaStatements(retentionDays int) []string {
	stmts := []string{
		`CREATE EXTENSION IF NOT EXISTS timescaledb`,
		`CREATE TABLE IF NOT EXISTS alerts (
			id             uuid        NOT NULL DEFAULT gen_random_uuid(),
			timestamp      timestamptz NOT NULL,
			server_name    text,
			rule_id        text,
			severity       text,
			scope          text        NOT NULL DEFAULT 'container',
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
			PRIMARY KEY (id, timestamp)
		)`,
		// Upgrade path for alerts tables created before host monitoring existed.
		`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS scope text NOT NULL DEFAULT 'container'`,
		`SELECT create_hypertable('alerts', 'timestamp', if_not_exists => TRUE)`,
		`CREATE INDEX IF NOT EXISTS alerts_container_ts ON alerts (container_id, timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS alerts_severity_ts ON alerts (severity, timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS alerts_rule_ts ON alerts (rule_id, timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS alerts_scope_ts ON alerts (scope, timestamp DESC)`,
		// Operator-defined false-positive suppression rules, managed via the API.
		// Mirrored by migrations/0002_suppressions.sql for fresh init runs.
		`CREATE TABLE IF NOT EXISTS suppressions (
			id             uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
			rule_id        text        NOT NULL DEFAULT '',
			scope          text        NOT NULL DEFAULT '',
			hostname       text        NOT NULL DEFAULT '',
			container_name text        NOT NULL DEFAULT '',
			process_name   text        NOT NULL DEFAULT '',
			substr         text        NOT NULL DEFAULT '',
			reason         text        NOT NULL DEFAULT '',
			created_by     text        NOT NULL DEFAULT '',
			created_at     timestamptz NOT NULL DEFAULT now()
		)`,
		// Upgrade path for suppressions tables created before host monitoring.
		`ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS scope text NOT NULL DEFAULT ''`,
		`ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS hostname text NOT NULL DEFAULT ''`,
	}
	if retentionDays > 0 {
		stmts = append(stmts, fmt.Sprintf(
			`SELECT add_retention_policy('alerts', INTERVAL '%d days', if_not_exists => TRUE)`,
			retentionDays))
	}
	return stmts
}
