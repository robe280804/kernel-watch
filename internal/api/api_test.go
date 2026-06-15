package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/config"
	"kernelwatch/internal/storage"
	"kernelwatch/internal/suppress"
)

const testToken = "s3cret-token-abcdef"

// fakeBackend records calls and returns canned data.
type fakeBackend struct {
	alerts      []alerter.Alert
	lastFilter  storage.AlertFilter
	stats       storage.StatsResult
	supps       suppress.Set
	added       suppress.Rule
	deleteFound bool
	fail        bool
}

func (f *fakeBackend) QueryAlerts(_ context.Context, flt storage.AlertFilter) ([]alerter.Alert, error) {
	f.lastFilter = flt
	if f.fail {
		return nil, errors.New("boom")
	}
	return f.alerts, nil
}
func (f *fakeBackend) Stats(_ context.Context, _ time.Time) (storage.StatsResult, error) {
	if f.fail {
		return storage.StatsResult{}, errors.New("boom")
	}
	return f.stats, nil
}
func (f *fakeBackend) ListSuppressions(_ context.Context) (suppress.Set, error) {
	return f.supps, nil
}
func (f *fakeBackend) AddSuppression(_ context.Context, r suppress.Rule) (suppress.Rule, error) {
	r.ID = "generated-id"
	r.CreatedAt = time.Unix(1700000000, 0)
	f.added = r
	return r, nil
}
func (f *fakeBackend) DeleteSuppression(_ context.Context, _ string) (bool, error) {
	return f.deleteFound, nil
}

func newTestServer(t *testing.T, backend Backend, onChange func()) *Server {
	t.Helper()
	cfg := &config.Config{APIBindAddr: "127.0.0.1", APIPort: 8080, APIToken: testToken}
	return New(cfg, backend, "test", onChange)
}

// do drives a request straight through the mux (no real listener).
func do(s *Server, method, target, token, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(rec, r)
	return rec
}

func TestHealthNeedsNoAuth(t *testing.T) {
	s := newTestServer(t, &fakeBackend{}, nil)
	rec := do(s, "GET", "/healthz", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("health should be 200, got %d", rec.Code)
	}
}

func TestAuthRequired(t *testing.T) {
	s := newTestServer(t, &fakeBackend{}, nil)
	if rec := do(s, "GET", "/api/v1/alerts", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token should be 401, got %d", rec.Code)
	}
	if rec := do(s, "GET", "/api/v1/alerts", "wrong-token", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token should be 401, got %d", rec.Code)
	}
}

func TestAlertsQueryPassesFilter(t *testing.T) {
	fb := &fakeBackend{alerts: []alerter.Alert{{ID: "1", Severity: alerter.SeverityHigh}}}
	s := newTestServer(t, fb, nil)

	rec := do(s, "GET", "/api/v1/alerts?severity=high&container=app&rule=network_tool&limit=5", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if fb.lastFilter.Severity != "high" || fb.lastFilter.Container != "app" ||
		fb.lastFilter.RuleID != "network_tool" || fb.lastFilter.Limit != 5 {
		t.Fatalf("filter not passed through: %+v", fb.lastFilter)
	}
	var resp struct {
		Count  int             `json:"count"`
		Alerts []alerter.Alert `json:"alerts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if resp.Count != 1 {
		t.Fatalf("expected 1 alert, got %d", resp.Count)
	}
}

func TestAlertsScopeFilter(t *testing.T) {
	fb := &fakeBackend{}
	s := newTestServer(t, fb, nil)

	if rec := do(s, "GET", "/api/v1/alerts?scope=host", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("scope=host should be 200, got %d", rec.Code)
	}
	if fb.lastFilter.Scope != "host" {
		t.Fatalf("scope filter not passed through: %+v", fb.lastFilter)
	}
	if rec := do(s, "GET", "/api/v1/alerts?scope=bogus", testToken, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid scope should be 400, got %d", rec.Code)
	}
}

func TestAddSuppressionScopeValidated(t *testing.T) {
	// A scope-only rule has no primary criteria → rejected as empty.
	s := newTestServer(t, &fakeBackend{}, nil)
	if rec := do(s, "POST", "/api/v1/suppressions", testToken, `{"scope":"host"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("scope-only rule should be 400 (empty), got %d", rec.Code)
	}
	// A valid rule narrowed by scope+hostname is accepted.
	fb := &fakeBackend{}
	s2 := newTestServer(t, fb, func() {})
	rec := do(s2, "POST", "/api/v1/suppressions", testToken,
		`{"rule_id":"host_tmp_exec","scope":"host","hostname":"web-01"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid host suppression should be 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	if fb.added.Scope != "host" || fb.added.Hostname != "web-01" {
		t.Fatalf("scope/hostname not forwarded: %+v", fb.added)
	}
	// An invalid scope value is rejected.
	s3 := newTestServer(t, &fakeBackend{}, nil)
	if rec := do(s3, "POST", "/api/v1/suppressions", testToken, `{"rule_id":"x","scope":"bogus"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid scope should be 400, got %d", rec.Code)
	}
}

func TestAlertsBadSince(t *testing.T) {
	s := newTestServer(t, &fakeBackend{}, nil)
	if rec := do(s, "GET", "/api/v1/alerts?since=notaduration", testToken, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad since should be 400, got %d", rec.Code)
	}
}

func TestAlertsBackendErrorIsOpaque(t *testing.T) {
	s := newTestServer(t, &fakeBackend{fail: true}, nil)
	rec := do(s, "GET", "/api/v1/alerts", testToken, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Fatalf("internal error detail leaked to client: %s", rec.Body.String())
	}
}

func TestAddSuppressionValid(t *testing.T) {
	fb := &fakeBackend{}
	changed := false
	s := newTestServer(t, fb, func() { changed = true })

	rec := do(s, "POST", "/api/v1/suppressions", testToken,
		`{"rule_id":"network_tool","container_name":"app","reason":"healthcheck curl"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	if fb.added.RuleID != "network_tool" || fb.added.ContainerName != "app" {
		t.Fatalf("rule not forwarded: %+v", fb.added)
	}
	if !changed {
		t.Fatal("onChange should fire after a successful add (detector reload)")
	}
	var got suppress.Rule
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.ID != "generated-id" {
		t.Fatalf("response should echo the created rule with id: %v / %+v", err, got)
	}
}

func TestAddSuppressionEmptyRejected(t *testing.T) {
	fb := &fakeBackend{}
	changed := false
	s := newTestServer(t, fb, func() { changed = true })

	rec := do(s, "POST", "/api/v1/suppressions", testToken, `{"reason":"oops nothing set"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty rule should be 400, got %d", rec.Code)
	}
	if changed {
		t.Fatal("onChange must not fire when the add is rejected")
	}
}

func TestAddSuppressionUnknownFieldRejected(t *testing.T) {
	s := newTestServer(t, &fakeBackend{}, nil)
	rec := do(s, "POST", "/api/v1/suppressions", testToken, `{"rule_id":"x","evil":"injected"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field should be 400, got %d", rec.Code)
	}
}

func TestDeleteSuppression(t *testing.T) {
	s := newTestServer(t, &fakeBackend{deleteFound: true}, nil)
	if rec := do(s, "DELETE", "/api/v1/suppressions/abc", testToken, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("existing delete should be 204, got %d", rec.Code)
	}

	s2 := newTestServer(t, &fakeBackend{deleteFound: false}, nil)
	if rec := do(s2, "DELETE", "/api/v1/suppressions/abc", testToken, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing delete should be 404, got %d", rec.Code)
	}
}

func TestNoBackendReturns503(t *testing.T) {
	s := newTestServer(t, nil, nil)
	if rec := do(s, "GET", "/api/v1/alerts", testToken, ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil backend should be 503, got %d", rec.Code)
	}
	// Health still works without a backend.
	if rec := do(s, "GET", "/healthz", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("health should still be 200, got %d", rec.Code)
	}
}

func TestParseSince(t *testing.T) {
	if ts, err := parseSince(""); err != nil || !ts.IsZero() {
		t.Fatalf("empty since should be zero time, no error")
	}
	if _, err := parseSince("24h"); err != nil {
		t.Fatalf("duration should parse: %v", err)
	}
	if _, err := parseSince("2023-01-02T15:04:05Z"); err != nil {
		t.Fatalf("RFC3339 should parse: %v", err)
	}
	if _, err := parseSince("garbage"); err == nil {
		t.Fatal("garbage should error")
	}
}
