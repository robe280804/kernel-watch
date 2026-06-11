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
	"kernelwatch/internal/collector"
	"kernelwatch/internal/config"
	"kernelwatch/internal/container"
	"kernelwatch/internal/detector"
	"kernelwatch/internal/storage"
)

// version is set at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

const (
	heartbeatInterval = 10 * time.Second
	heartbeatMaxAge   = 30 * time.Second // staleness threshold for the -health check
)

func main() {
	var showVersion, healthCheck bool
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&healthCheck, "health", false, "check the heartbeat file and exit (0=healthy, 1=unhealthy)")
	flag.Parse()

	if showVersion {
		fmt.Println("kernelwatch", version)
		return
	}
	if healthCheck {
		os.Exit(runHealthCheck())
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
	)

	// ── Build components ──────────────────────────────────────────────────────
	mapper := container.New(5 * time.Minute)

	// Optional alert persistence (best-effort; never blocks monitoring).
	var sink alerter.AlertSink
	if cfg.DBEnabled {
		store := storage.New(cfg)
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
