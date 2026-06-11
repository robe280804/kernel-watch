package main

// NOTE: eBPF code generation lives in internal/collector/gen.go so the generated
// scaffolding lands in the collector package (where it is used). Run with:
//   go generate ./...

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"containersentry/internal/alerter"
	"containersentry/internal/collector"
	"containersentry/internal/config"
	"containersentry/internal/container"
	"containersentry/internal/detector"
)

func main() {
	// ── Structured logging ────────────────────────────────────────────────────
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	slog.Info("ContainerSentry starting")

	// ── Load config from environment ──────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}
	slog.Info("config loaded",
		"server", cfg.ServerName,
		"min_severity", cfg.AlertMinSeverity,
		"webhook", cfg.WebhookEnabled,
		"slack", cfg.SlackEnabled,
	)

	// ── Build components ──────────────────────────────────────────────────────
	mapper := container.New(5 * time.Minute)

	alert, err := alerter.New(cfg)
	if err != nil {
		slog.Error("alerter init", "err", err)
		os.Exit(1)
	}
	defer alert.Close()

	detect := detector.New()
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

	// ── Signal handling ───────────────────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ── Main event loop ───────────────────────────────────────────────────────
	var processed, alerted uint64

	for {
		select {
		case event, ok := <-events:
			if !ok {
				slog.Info("event stream closed, shutting down")
				return
			}
			processed++

			// Run detection rules
			if a := detect.Check(event); a != nil {
				alerted++
				alert.Send(a)
			}

			// Periodic stats log
			if processed%10000 == 0 {
				slog.Info("stats",
					"processed", processed,
					"alerted", alerted,
				)
			}

		case <-ctx.Done():
			slog.Info("shutdown signal received",
				"processed", processed,
				"alerted", alerted,
			)
			return
		}
	}
}
