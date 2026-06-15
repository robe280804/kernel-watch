// Package api exposes a small, authenticated REST API for querying the alert /
// incident history and managing operator false-positive suppressions — the
// "track attacks on the server" surface.
//
// Security posture by default:
//   - binds to 127.0.0.1 (KW_API_BIND_ADDR) — never the public internet unless
//     the operator deliberately changes it and fronts it with TLS;
//   - every data endpoint requires a Bearer token, compared in constant time;
//   - request bodies and headers are size-capped and the server has read/write
//     timeouts, so a slow-loris or oversized body cannot tie it up;
//   - it is strictly read/manage — it never exposes the ability to disable
//     monitoring or run anything on the host.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/config"
	"kernelwatch/internal/storage"
	"kernelwatch/internal/suppress"
)

// Backend is the data layer the API reads from and writes suppressions to —
// satisfied by *storage.Store. It is an interface so the HTTP layer is testable
// without a database.
type Backend interface {
	QueryAlerts(context.Context, storage.AlertFilter) ([]alerter.Alert, error)
	Stats(context.Context, time.Time) (storage.StatsResult, error)
	ListSuppressions(context.Context) (suppress.Set, error)
	AddSuppression(context.Context, suppress.Rule) (suppress.Rule, error)
	DeleteSuppression(context.Context, string) (bool, error)
}

const (
	maxBodyBytes      = 64 << 10        // 64 KiB cap on request bodies
	defaultStatsRange = 24 * time.Hour  // /stats window when 'since' is omitted
	queryTimeout      = 10 * time.Second
)

// Server is the KernelWatch REST API.
type Server struct {
	addr     string
	token    string
	version  string
	backend  Backend   // nil when persistence is disabled (data endpoints → 503)
	onChange func()     // called after a suppression mutation so the detector can reload
	srv      *http.Server
}

// New builds the server. backend may be nil (KW_DB_ENABLED=false); onChange may
// be nil.
func New(cfg *config.Config, backend Backend, version string, onChange func()) *Server {
	s := &Server{
		addr:     net.JoinHostPort(cfg.APIBindAddr, strconv.Itoa(cfg.APIPort)),
		token:    cfg.APIToken,
		version:  version,
		backend:  backend,
		onChange: onChange,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/v1/alerts", s.auth(s.handleAlerts))
	mux.HandleFunc("GET /api/v1/stats", s.auth(s.handleStats))
	mux.HandleFunc("GET /api/v1/suppressions", s.auth(s.handleListSuppressions))
	mux.HandleFunc("POST /api/v1/suppressions", s.auth(s.handleAddSuppression))
	mux.HandleFunc("DELETE /api/v1/suppressions/{id}", s.auth(s.handleDeleteSuppression))

	s.srv = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	return s
}

// Start binds the listener (so bind errors surface immediately) and serves in a
// background goroutine.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("api listen on %s: %w", s.addr, err)
	}
	slog.Info("REST API listening", "addr", s.addr, "persistence", s.backend != nil)
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("api server stopped", "err", err)
		}
	}()
	return nil
}

// Stop gracefully shuts the server down.
func (s *Server) Stop(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// ── Middleware ────────────────────────────────────────────────────────────────

// auth enforces a Bearer token using a constant-time comparison so the endpoint
// cannot be used as a timing oracle.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	want := []byte(s.token)
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, prefix) {
			writeErr(w, http.StatusUnauthorized, "missing or malformed Authorization header")
			return
		}
		got := []byte(strings.TrimSpace(h[len(prefix):]))
		if len(want) == 0 || subtle.ConstantTimeCompare(got, want) != 1 {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next(w, r)
	}
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"version":     s.version,
		"persistence": s.backend != nil,
	})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.requireBackend(w) {
		return
	}
	q := r.URL.Query()

	since, err := parseSince(q.Get("since"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	scope := q.Get("scope")
	if !validScope(scope) {
		writeErr(w, http.StatusBadRequest, "scope must be 'host' or 'container'")
		return
	}
	f := storage.AlertFilter{
		Severity:  q.Get("severity"),
		Scope:     scope,
		Container: q.Get("container"),
		RuleID:    q.Get("rule"),
		Since:     since,
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		f.Limit = n
	}

	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	alerts, err := s.backend.QueryAlerts(ctx, f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		slog.Error("api: query alerts", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(alerts), "alerts": alerts})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireBackend(w) {
		return
	}
	since, err := parseSince(r.URL.Query().Get("since"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if since.IsZero() {
		since = time.Now().Add(-defaultStatsRange)
	}

	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	stats, err := s.backend.Stats(ctx, since)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "stats failed")
		slog.Error("api: stats", "err", err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleListSuppressions(w http.ResponseWriter, r *http.Request) {
	if !s.requireBackend(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	set, err := s.backend.ListSuppressions(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list failed")
		slog.Error("api: list suppressions", "err", err)
		return
	}
	if set == nil {
		set = suppress.Set{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(set), "suppressions": set})
}

func (s *Server) handleAddSuppression(w http.ResponseWriter, r *http.Request) {
	if !s.requireBackend(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var rule suppress.Rule
	if err := dec.Decode(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if rule.Empty() {
		writeErr(w, http.StatusBadRequest, "at least one of rule_id, container_name, process_name, substr must be set (scope/hostname only narrow an existing rule)")
		return
	}
	if !validScope(rule.Scope) {
		writeErr(w, http.StatusBadRequest, "scope must be 'host' or 'container'")
		return
	}
	// Server-controlled fields are never taken from the client.
	rule.ID = ""
	rule.CreatedAt = time.Time{}

	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	created, err := s.backend.AddSuppression(ctx, rule)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create failed")
		slog.Error("api: add suppression", "err", err)
		return
	}
	s.notifyChange()
	slog.Info("suppression added via API", "id", created.ID, "rule", created.RuleID, "container", created.ContainerName)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleDeleteSuppression(w http.ResponseWriter, r *http.Request) {
	if !s.requireBackend(w) {
		return
	}
	id := r.PathValue("id")

	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	found, err := s.backend.DeleteSuppression(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		slog.Error("api: delete suppression", "err", err)
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "no suppression with that id")
		return
	}
	s.notifyChange()
	slog.Info("suppression deleted via API", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// ── helpers ────────────────────────────────────────────────────────────────

func (s *Server) requireBackend(w http.ResponseWriter) bool {
	if s.backend == nil {
		writeErr(w, http.StatusServiceUnavailable, "alert storage is disabled (set KW_DB_ENABLED=true to use this endpoint)")
		return false
	}
	return true
}

func (s *Server) notifyChange() {
	if s.onChange != nil {
		s.onChange()
	}
}

// validScope reports whether a scope query/field is acceptable: empty (any) or
// one of the two known scopes.
func validScope(s string) bool {
	switch s {
	case "", alerter.ScopeHost, alerter.ScopeContainer:
		return true
	default:
		return false
	}
}

// parseSince accepts an empty string (zero time), a Go duration ("24h", "30m"
// → now minus that), or an RFC3339 timestamp.
func parseSince(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, errors.New("invalid 'since': use a duration like 24h or an RFC3339 timestamp")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
