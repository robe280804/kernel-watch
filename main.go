package main

// NOTE: eBPF code generation lives in internal/collector/gen.go so the generated
// scaffolding lands in the collector package (where it is used). Run with:
//   go generate ./...

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/api"
	"kernelwatch/internal/collector"
	"kernelwatch/internal/config"
	"kernelwatch/internal/container"
	"kernelwatch/internal/correlator"
	"kernelwatch/internal/detector"
	"kernelwatch/internal/logtail"
	"kernelwatch/internal/ruleengine"
	"kernelwatch/internal/storage"
)

// version is set at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

const (
	heartbeatInterval = 10 * time.Second
	heartbeatMaxAge   = 30 * time.Second // staleness threshold for the -health check
)

func main() {
	var showVersion, healthCheck, validateRules bool
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&healthCheck, "health", false, "check the heartbeat file and exit (0=healthy, 1=unhealthy)")
	flag.BoolVar(&validateRules, "validate", false, "validate the ruleset (embedded + KW_RULES_FILE/KW_RULES_DIR) and exit (0=ok, 1=invalid)")
	flag.Parse()

	if showVersion {
		fmt.Println("kernelwatch", version)
		return
	}
	if healthCheck {
		os.Exit(runHealthCheck())
	}
	if validateRules {
		os.Exit(runValidateRules())
	}

	// ── Structured logging ────────────────────────────────────────────────────
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	slog.Info("KernelWatch starting", "version", version)

	// ── Load config from environment ──────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}
	slog.Info("config loaded",
		"server", cfg.ServerName,
		"mode", cfg.Mode,
		"min_severity", cfg.AlertMinSeverity,
		"webhook", cfg.WebhookEnabled,
		"slack", cfg.SlackEnabled,
		"db_enabled", cfg.DBEnabled,
		"monitor_host", cfg.MonitorHost,
	)

	// Fail fast on a broken operator ruleset at startup (deliberate divergence
	// from the runtime hot-reload path, which keeps the last-good ruleset).
	if cfg.RulesFile != "" || cfg.RulesDir != "" {
		if err := ruleengine.Validate(cfg.RulesFile, cfg.RulesDir); err != nil {
			slog.Error("rule engine validation failed", "err", err)
			os.Exit(1)
		}
		slog.Info("custom ruleset loaded", "file", cfg.RulesFile, "dir", cfg.RulesDir)
	}

	// ── Build components ──────────────────────────────────────────────────────
	mapper := container.New(5 * time.Minute)

	// Optional alert persistence (best-effort; never blocks monitoring). The
	// concrete store is kept (not just the sink interface) so the REST API can
	// query the alert history and manage suppressions through it.
	var sink alerter.AlertSink
	var store *storage.Store
	if cfg.DBEnabled {
		store = storage.New(cfg)
		defer store.Close()
		sink = store
	}

	alert, err := alerter.New(cfg, sink)
	if err != nil {
		slog.Error("alerter init", "err", err)
		os.Exit(1)
	}
	defer alert.Close()

	detect := detector.New(cfg)
	coll := collector.New(cfg, mapper)

	// Attack-chain correlation: consolidates a container's findings into one
	// escalated incident when they span multiple kill-chain stages. nil when
	// disabled, in which case Observe is simply never called.
	var correlate *correlator.Correlator
	if cfg.CorrelationEnabled {
		correlate = correlator.New(correlator.Config{
			Window:        time.Duration(cfg.CorrelationWindow) * time.Second,
			MinStages:     cfg.CorrelationMinStages,
			MinScore:      cfg.CorrelationMinScore,
			Cooldown:      time.Duration(cfg.CorrelationCooldown) * time.Second,
			HostMinStages: cfg.CorrelationHostMinStages,
			HostMinScore:  cfg.CorrelationHostMinScore,
		})
		slog.Info("attack-chain correlation enabled",
			"window_s", cfg.CorrelationWindow,
			"min_stages", cfg.CorrelationMinStages,
			"min_score", cfg.CorrelationMinScore,
		)
	}

	// ── Start eBPF collector ──────────────────────────────────────────────────
	events, err := coll.Start()
	if err != nil {
		slog.Error("collector start", "err", err)
		slog.Error("hint: run as root (or with CAP_SYS_ADMIN) on Linux kernel 5.15+")
		os.Exit(1)
	}
	defer coll.Stop()

	slog.Info("monitoring started", "server", cfg.ServerName)

	// Heartbeat directory + first write, so the healthcheck passes immediately.
	if err := os.MkdirAll(filepath.Dir(cfg.HealthFile), 0o755); err != nil {
		slog.Warn("heartbeat dir", "err", err)
	}

	// ── Signal handling ───────────────────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ── REST API + live suppression reload ─────────────────────────────────────
	// Operator-defined false-positive suppressions live in the database and are
	// reloaded into the detector both on a short interval (covers changes from
	// other instances) and immediately after an API mutation (onChange).
	if store != nil {
		reloadSuppressions(ctx, store, detect)        // best-effort initial load
		go suppressionReloader(ctx, store, detect)    // periodic refresh
	}

	// Hot-reload the YAML ruleset (operator file/dir) on a short interval, so rule
	// changes take effect without a restart. Only started when a custom ruleset is
	// configured (the embedded default is immutable). A failed reload keeps the
	// previous ruleset — the monitor never disarms.
	if cfg.RulesFile != "" || cfg.RulesDir != "" {
		go rulesReloader(ctx, cfg, detect)
	}
	if cfg.APIEnabled {
		var backend api.Backend
		if store != nil {
			backend = store
		}
		apiSrv := api.New(cfg, backend, version, func() {
			if store != nil {
				reloadSuppressions(ctx, store, detect)
			}
		})
		if err := apiSrv.Start(); err != nil {
			slog.Error("api start", "err", err)
			os.Exit(1)
		}
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = apiSrv.Stop(sctx)
		}()
	}

	// ── SSH brute-force auth-log tailer ────────────────────────────────────────
	// eBPF cannot see authentication outcomes, so credential-stuffing detection
	// comes from the host auth log. Synthesized alerts flow into the same Send
	// path (and thus correlation, persistence, and SIEM output) as eBPF findings.
	if cfg.AuthLogEnabled {
		tailer := logtail.New(logtail.Config{
			Path:       cfg.AuthLogPath,
			Threshold:  cfg.SSHBruteThreshold,
			Window:     time.Duration(cfg.SSHBruteWindow) * time.Second,
			ServerName: cfg.ServerName,
		}, func(a *alerter.Alert) {
			alert.Send(a)
			if correlate != nil {
				if inc := correlate.Observe(a); inc != nil {
					alert.Send(inc)
				}
			}
		})
		go tailer.Run(ctx)
	}

	// ── Main event loop ───────────────────────────────────────────────────────
	var processed, alerted uint64

	hb := time.NewTicker(heartbeatInterval)
	defer hb.Stop()
	writeHeartbeat(cfg.HealthFile, coll.Stats(), processed, alerted)

	for {
		select {
		case event, ok := <-events:
			if !ok {
				slog.Info("event stream closed, shutting down")
				return
			}
			processed++

			// Run detection rules (one event may raise several findings)
			for _, a := range detect.Check(event) {
				alerted++
				alert.Send(a)
				// Feed every finding to the correlator (before any severity
				// filtering) so low-signal recon still counts toward a chain. A
				// returned incident is dispatched as its own escalated alert.
				if correlate != nil {
					if inc := correlate.Observe(a); inc != nil {
						alerted++
						alert.Send(inc)
					}
				}
			}

		case <-hb.C:
			// Liveness heartbeat + periodic stats (surfaces event loss).
			s := coll.Stats()
			writeHeartbeat(cfg.HealthFile, s, processed, alerted)
			slog.Info("stats",
				"processed", processed,
				"alerted", alerted,
				"kernel_drops", s.KernelDrops,
				"channel_drops", s.ChannelDrops,
				"enrich_miss_argv", s.EnrichMissArgv,
				"enrich_miss_ancestry", s.EnrichMissAncestry,
			)

		case <-ctx.Done():
			slog.Info("shutdown signal received",
				"processed", processed,
				"alerted", alerted,
			)
			return
		}
	}
}

// writeHeartbeat atomically writes a liveness file the `-health` subcommand
// checks. Its freshness proves the main loop is alive and draining events; the
// counters make event loss observable.
func writeHeartbeat(path string, s collector.Stats, processed, alerted uint64) {
	if path == "" {
		return
	}
	data, _ := json.Marshal(map[string]any{
		"time":                 time.Now().UTC().Format(time.RFC3339),
		"processed":            processed,
		"alerted":              alerted,
		"kernel_drops":         s.KernelDrops,
		"channel_drops":        s.ChannelDrops,
		"enrich_miss_argv":     s.EnrichMissArgv,
		"enrich_miss_ancestry": s.EnrichMissAncestry,
	})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		slog.Debug("heartbeat write", "err", err)
		return
	}
	_ = os.Rename(tmp, path)
}

// reloadSuppressions loads the active suppression set from the store into the
// detector. Best-effort: a transient DB error (e.g. before the schema exists)
// just leaves the previous set in place until the next reload.
func reloadSuppressions(ctx context.Context, store *storage.Store, detect *detector.Detector) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	set, err := store.ListSuppressions(cctx)
	if err != nil {
		slog.Debug("suppression reload skipped", "err", err)
		return
	}
	detect.SetSuppressions(set)
	slog.Debug("suppressions reloaded", "count", len(set))
}

// suppressionReloader periodically refreshes the detector's suppression set so
// changes made via the API (including from another instance) take effect without
// a restart. Stops when ctx is cancelled.
func suppressionReloader(ctx context.Context, store *storage.Store, detect *detector.Detector) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			reloadSuppressions(ctx, store, detect)
		}
	}
}

// runValidateRules is the `--validate` subcommand: compiles the embedded ruleset
// plus any KW_RULES_FILE/KW_RULES_DIR overlays and reports the result. Needs
// neither root nor eBPF, so CI and operators can lint a rules file safely.
func runValidateRules() int {
	file := os.Getenv("KW_RULES_FILE")
	dir := os.Getenv("KW_RULES_DIR")
	if err := ruleengine.Validate(file, dir); err != nil {
		fmt.Fprintln(os.Stderr, "ruleset invalid:", err)
		return 1
	}
	fmt.Println("ruleset OK")
	return 0
}

// reloadRules recompiles the ruleset (embedded + operator overlays) and swaps it
// into the detector. Best-effort: a transient parse/compile error leaves the
// previous ruleset in place so the monitor keeps running.
func reloadRules(cfg *config.Config, detect *detector.Detector) {
	eng, err := ruleengine.Load(cfg.RulesFile, cfg.RulesDir)
	if err != nil {
		slog.Warn("ruleset reload skipped (keeping previous)", "err", err)
		return
	}
	detect.SetRuleset(eng)
	slog.Debug("ruleset reloaded")
}

// rulesReloader periodically reloads the ruleset so operator edits take effect
// without a restart. Stops when ctx is cancelled.
func rulesReloader(ctx context.Context, cfg *config.Config, detect *detector.Detector) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			reloadRules(cfg, detect)
		}
	}
}

// runHealthCheck is the `-health` subcommand: exits 0 if the heartbeat file is
// fresh, 1 otherwise. Reads the path from the environment so it never depends on
// full config validation.
func runHealthCheck() int {
	path := os.Getenv("KW_HEALTH_FILE")
	if path == "" {
		path = "/var/log/kernelwatch/health"
	}
	fi, err := os.Stat(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "health: no heartbeat:", err)
		return 1
	}
	if age := time.Since(fi.ModTime()); age > heartbeatMaxAge {
		fmt.Fprintf(os.Stderr, "health: stale heartbeat (age %s)\n", age.Round(time.Second))
		return 1
	}
	return 0
}
