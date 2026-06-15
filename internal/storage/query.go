package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/suppress"
)

// errNoQuerier is returned by the read-path methods when the Store has no
// database behind it (i.e. it was built for unit tests, not via New).
var errNoQuerier = errors.New("storage: read path unavailable")

// AlertFilter narrows an alert history query. Zero-valued fields are ignored.
type AlertFilter struct {
	Severity  string    // exact match (low/medium/high/critical)
	Scope     string    // exact match (host/container)
	Container string    // exact container name
	RuleID    string    // exact detection rule id ("attack_chain" = incidents)
	Since     time.Time // only alerts at/after this time (zero = no lower bound)
	Limit     int       // max rows (clamped to 1..maxAlertLimit, default defaultAlertLimit)
}

const (
	defaultAlertLimit = 100
	maxAlertLimit     = 1000
)

// Count is a single (key, count) pair in an aggregate.
type Count struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// StatsResult is the aggregate view returned by /stats.
type StatsResult struct {
	Since         time.Time `json:"since"`
	Total         int64     `json:"total"`
	BySeverity    []Count   `json:"by_severity"`
	ByScope       []Count   `json:"by_scope"`
	ByRule        []Count   `json:"by_rule"`
	TopContainers []Count   `json:"top_containers"`
}

// querier is the read path, implemented by *pgInserter. It is unexported because
// callers go through the exported Store methods below.
type querier interface {
	queryAlerts(ctx context.Context, f AlertFilter) ([]alerter.Alert, error)
	stats(ctx context.Context, since time.Time) (StatsResult, error)
	listSuppressions(ctx context.Context) (suppress.Set, error)
	addSuppression(ctx context.Context, r suppress.Rule) (suppress.Rule, error)
	deleteSuppression(ctx context.Context, id string) (bool, error)
}

// ── Store delegations (the API talks to these) ───────────────────────────────

// QueryAlerts returns recent alerts matching the filter, newest first.
func (s *Store) QueryAlerts(ctx context.Context, f AlertFilter) ([]alerter.Alert, error) {
	if s == nil || s.q == nil {
		return nil, errNoQuerier
	}
	return s.q.queryAlerts(ctx, f)
}

// Stats returns aggregate counts over the window [since, now].
func (s *Store) Stats(ctx context.Context, since time.Time) (StatsResult, error) {
	if s == nil || s.q == nil {
		return StatsResult{}, errNoQuerier
	}
	return s.q.stats(ctx, since)
}

// ListSuppressions returns all active suppression rules, newest first.
func (s *Store) ListSuppressions(ctx context.Context) (suppress.Set, error) {
	if s == nil || s.q == nil {
		return nil, errNoQuerier
	}
	return s.q.listSuppressions(ctx)
}

// AddSuppression persists a new suppression rule and returns it with its
// generated id and timestamp.
func (s *Store) AddSuppression(ctx context.Context, r suppress.Rule) (suppress.Rule, error) {
	if s == nil || s.q == nil {
		return suppress.Rule{}, errNoQuerier
	}
	return s.q.addSuppression(ctx, r)
}

// DeleteSuppression removes a suppression rule by id. The bool reports whether a
// row was actually deleted (false = not found).
func (s *Store) DeleteSuppression(ctx context.Context, id string) (bool, error) {
	if s == nil || s.q == nil {
		return false, errNoQuerier
	}
	return s.q.deleteSuppression(ctx, id)
}

// ── pgInserter read-path implementation ──────────────────────────────────────

const alertColumns = `id::text, timestamp, server_name, rule_id, severity, scope, container_id,
	container_name, image_name, syscall, pid, process_name, parent_name, ancestry,
	cmdline, reason, mitre_ttp, mitre_tactic, tags, details`

func (p *pgInserter) queryAlerts(ctx context.Context, f AlertFilter) ([]alerter.Alert, error) {
	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}

	var (
		conds []string
		args  []any
	)
	add := func(col, val string) {
		if val == "" {
			return
		}
		args = append(args, val)
		conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	add("severity", f.Severity)
	add("scope", f.Scope)
	add("container_name", f.Container)
	add("rule_id", f.RuleID)
	if !f.Since.IsZero() {
		args = append(args, f.Since)
		conds = append(conds, fmt.Sprintf("timestamp >= $%d", len(args)))
	}

	sql := "SELECT " + alertColumns + " FROM alerts"
	if len(conds) > 0 {
		sql += " WHERE " + strings.Join(conds, " AND ")
	}
	sql += " ORDER BY timestamp DESC"

	limit := f.Limit
	if limit <= 0 {
		limit = defaultAlertLimit
	}
	if limit > maxAlertLimit {
		limit = maxAlertLimit
	}
	args = append(args, limit)
	sql += fmt.Sprintf(" LIMIT $%d", len(args))

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]alerter.Alert, 0, limit)
	for rows.Next() {
		var (
			a       alerter.Alert
			sev     string
			pid     int64
			details []byte
		)
		if err := rows.Scan(
			&a.ID, &a.Timestamp, &a.ServerName, &a.RuleID, &sev, &a.Scope, &a.ContainerID,
			&a.ContainerName, &a.ImageName, &a.Syscall, &pid, &a.ProcessName, &a.ParentName,
			&a.Ancestry, &a.CmdLine, &a.Reason, &a.MITRETTP, &a.MITRETactic, &a.Tags, &details,
		); err != nil {
			return nil, err
		}
		a.Severity = alerter.Severity(sev)
		a.PID = uint32(pid)
		if len(details) > 0 {
			_ = json.Unmarshal(details, &a.Details)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *pgInserter) stats(ctx context.Context, since time.Time) (StatsResult, error) {
	pool, err := p.getPool(ctx)
	if err != nil {
		return StatsResult{}, err
	}
	res := StatsResult{Since: since}

	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM alerts WHERE timestamp >= $1`, since,
	).Scan(&res.Total); err != nil {
		return StatsResult{}, err
	}

	group := func(col string, limit int) ([]Count, error) {
		sql := fmt.Sprintf(
			`SELECT coalesce(%s,'') AS k, count(*) AS c FROM alerts
			 WHERE timestamp >= $1 GROUP BY k ORDER BY c DESC`, col)
		if limit > 0 {
			sql += fmt.Sprintf(" LIMIT %d", limit)
		}
		rows, err := pool.Query(ctx, sql, since)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var counts []Count
		for rows.Next() {
			var c Count
			if err := rows.Scan(&c.Key, &c.Count); err != nil {
				return nil, err
			}
			counts = append(counts, c)
		}
		return counts, rows.Err()
	}

	if res.BySeverity, err = group("severity", 0); err != nil {
		return StatsResult{}, err
	}
	if res.ByScope, err = group("scope", 0); err != nil {
		return StatsResult{}, err
	}
	if res.ByRule, err = group("rule_id", 0); err != nil {
		return StatsResult{}, err
	}
	if res.TopContainers, err = group("container_name", 20); err != nil {
		return StatsResult{}, err
	}
	return res, nil
}

func (p *pgInserter) listSuppressions(ctx context.Context) (suppress.Set, error) {
	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(ctx,
		`SELECT id::text, rule_id, scope, hostname, container_name, process_name, substr, reason, created_by, created_at
		 FROM suppressions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var set suppress.Set
	for rows.Next() {
		var r suppress.Rule
		if err := rows.Scan(&r.ID, &r.RuleID, &r.Scope, &r.Hostname, &r.ContainerName, &r.ProcessName,
			&r.Substr, &r.Reason, &r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		set = append(set, r)
	}
	return set, rows.Err()
}

func (p *pgInserter) addSuppression(ctx context.Context, r suppress.Rule) (suppress.Rule, error) {
	pool, err := p.getPool(ctx)
	if err != nil {
		return suppress.Rule{}, err
	}
	err = pool.QueryRow(ctx,
		`INSERT INTO suppressions (rule_id, scope, hostname, container_name, process_name, substr, reason, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id::text, created_at`,
		strings.TrimSpace(r.RuleID), strings.TrimSpace(r.Scope), strings.TrimSpace(r.Hostname),
		strings.TrimSpace(r.ContainerName), strings.TrimSpace(r.ProcessName), strings.TrimSpace(r.Substr),
		strings.TrimSpace(r.Reason), strings.TrimSpace(r.CreatedBy),
	).Scan(&r.ID, &r.CreatedAt)
	if err != nil {
		return suppress.Rule{}, err
	}
	return r, nil
}

func (p *pgInserter) deleteSuppression(ctx context.Context, id string) (bool, error) {
	pool, err := p.getPool(ctx)
	if err != nil {
		return false, err
	}
	// Compare as text so a malformed id yields "not found" rather than a type
	// error from uuid encoding.
	tag, err := pool.Exec(ctx, `DELETE FROM suppressions WHERE id::text = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
