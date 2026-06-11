package storage

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"kernelwatch/internal/alerter"
)

// fakeInserter is an in-memory inserter for offline tests (no Postgres).
type fakeInserter struct {
	mu          sync.Mutex
	inserted    []row
	schemaCalls int
	blockInsert chan struct{} // if non-nil, insertBatch blocks until closed
	failInsert  bool
}

func (f *fakeInserter) ensureSchema(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.schemaCalls++
	return nil
}

func (f *fakeInserter) insertBatch(ctx context.Context, rows []row) error {
	if f.blockInsert != nil {
		<-f.blockInsert
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failInsert {
		return errors.New("insert failed")
	}
	f.inserted = append(f.inserted, rows...)
	return nil
}

func (f *fakeInserter) close() {}

func (f *fakeInserter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.inserted)
}

func TestToRowMapping(t *testing.T) {
	a := &alerter.Alert{
		Timestamp:   time.Unix(1700000000, 0),
		ServerName:  "host1",
		RuleID:      "shell_in_container",
		Severity:    alerter.SeverityCritical,
		ContainerID: "abc",
		PID:         4321,
		Ancestry:    []string{"sh", "nginx"},
		Tags:        []string{"container", "shell"},
		Details:     map[string]any{"shell": "bash", "spawned_by": "nginx"},
		MITRETTP:    "T1059",
	}
	r := toRow(a)
	if r.Severity != "critical" || r.RuleID != "shell_in_container" || r.PID != 4321 {
		t.Fatalf("scalar mapping wrong: %+v", r)
	}
	if len(r.Ancestry) != 2 || r.Ancestry[1] != "nginx" {
		t.Fatalf("ancestry mapping wrong: %v", r.Ancestry)
	}
	var got map[string]any
	if err := json.Unmarshal(r.Details, &got); err != nil {
		t.Fatalf("details is not valid json: %v (%s)", err, r.Details)
	}
	if got["spawned_by"] != "nginx" {
		t.Fatalf("details content wrong: %v", got)
	}
}

func TestToRowNilDetails(t *testing.T) {
	r := toRow(&alerter.Alert{Severity: alerter.SeverityLow})
	if r.Details != nil {
		t.Fatalf("expected nil details (SQL NULL), got %s", r.Details)
	}
}

func TestStoreFlushesOnClose(t *testing.T) {
	f := &fakeInserter{}
	s := newStore(f)
	const n = 250
	for i := 0; i < n; i++ {
		s.Save(&alerter.Alert{Severity: alerter.SeverityHigh, RuleID: "r", ContainerID: "c"})
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := f.count(); got != n {
		t.Fatalf("inserted %d, want %d", got, n)
	}
}

func TestStoreDropsWhenBufferFull(t *testing.T) {
	f := &fakeInserter{blockInsert: make(chan struct{})}
	s := newStore(f)

	// Worker takes one batch then blocks on insert; the channel (cap bufferSize)
	// fills, and further Saves must drop rather than block.
	total := bufferSize + batchSize + 500
	for i := 0; i < total; i++ {
		s.Save(&alerter.Alert{Severity: alerter.SeverityHigh, ContainerID: "c"})
	}
	if s.dropped.Load() == 0 {
		t.Fatalf("expected some drops when buffer full, got 0")
	}

	close(f.blockInsert) // unblock so Close can finish
	_ = s.Close()
}

func TestSchemaStatementsRetention(t *testing.T) {
	with := schemaStatements(90)
	if len(with) == 0 || !contains(with, "add_retention_policy") {
		t.Fatal("expected a retention policy statement when days>0")
	}
	without := schemaStatements(0)
	if contains(without, "add_retention_policy") {
		t.Fatal("did not expect a retention policy statement when days=0")
	}
}

func contains(stmts []string, substr string) bool {
	for _, s := range stmts {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
	}
	return false
}
