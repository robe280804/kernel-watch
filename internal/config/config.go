package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all runtime configuration read from environment variables.
// Every field maps 1:1 to a KW_* env var defined in .env.example.
type Config struct {
	// Server identity
	ServerName string

	// Detection mode: "alert" (default) dispatches alerts; "monitor" is dry-run —
	// rules are evaluated and logged but webhook/Slack are never called.
	Mode string

	// Detection ruleset (YAML). Empty = use only the embedded default ruleset.
	// RulesFile is a single overlay file; RulesDir is a directory of *.yaml
	// overlays applied in lexical order. Both merge on top of the defaults
	// (override / append semantics).
	RulesFile string
	RulesDir  string

	// Process-lineage detection tuning
	AncestryDepth       int      // ancestors to resolve per execve (default 5)
	TrustedParents      []string // extra parent comms treated as benign supervisors/schedulers
	NetworkParents      []string // extra parent comms treated as network-facing (attack surface)
	DetectionExceptions []string // suppress matches by image/name/ancestry/argv substring

	// Host (whole-server) monitoring. Opt-in: when false (default) every host
	// event is dropped at the collector, so behavior is byte-for-byte identical to
	// the container-only build. When true, host-scope events (PIDs not in a
	// container) are collected, enriched, and evaluated by the host ruleset.
	MonitorHost        bool
	HostOpenWatchExtra []string // extra path prefixes to watch on host openat (allowlist)
	HostExecExclude    []string // comm names to exclude on host execve (fleet agents)
	HostTrustedWriters []string // extra trusted writers for host persistence rules
	HostTrustedParents []string // extra trusted parent comms for host-scope classification
	HostDockerClients  []string // extra comm names allowed to open docker.sock on host

	// Container filtering
	ContainerWhitelist []string // empty = monitor all
	ContainerBlacklist []string

	// Alert thresholds
	AlertMinSeverity string
	AlertMaxRate     int
	AlertRateWindow  int // seconds

	// Alert output format: "native" (enriched KernelWatch JSON, default) or
	// "ecs" (Elastic Common Schema) for direct SIEM ingestion. Applies to the log
	// file and webhook bodies; Slack always uses the human-readable format.
	AlertFormat string

	// Attack-chain correlation: when several findings from the same container's
	// process tree span multiple MITRE kill-chain stages inside a window, emit one
	// consolidated, escalated "attack chain" incident instead of disconnected
	// alerts. This both raises true-positive confidence and cuts alert fatigue.
	CorrelationEnabled   bool
	CorrelationWindow    int // sliding correlation window (seconds)
	CorrelationMinStages int // distinct kill-chain stages required to raise an incident
	CorrelationMinScore  int // OR: accumulated risk score required to raise an incident
	CorrelationCooldown  int // minimum seconds between incidents for the same container
	// Host-bucket overrides: fleets generally want a wider chain on the noisier
	// host scope before raising an incident. 0 = inherit the container thresholds.
	CorrelationHostMinStages int
	CorrelationHostMinScore  int

	// SSH brute-force auth-log tailer (eBPF cannot see auth outcomes). Opt-in.
	AuthLogEnabled    bool
	AuthLogPath       string
	SSHBruteThreshold int // failed attempts per source IP within the window
	SSHBruteWindow    int // sliding window (seconds)

	// Alert destinations
	LogEnabled    bool
	LogPath       string
	LogMaxMB      int // rotate alerts.json past this size (0 = no rotation)
	LogMaxBackups int // how many rotated files to keep
	WebhookEnabled bool
	WebhookURL     string
	WebhookSecret  string
	SlackEnabled      bool
	SlackWebhookURL   string
	SlackChannel      string

	// API
	APIEnabled  bool   // expose the REST API (off by default — opt-in network surface)
	APIBindAddr string // interface to bind (default 127.0.0.1 — never 0.0.0.0 unless deliberate)
	APIPort     int
	APIToken    string

	// eBPF
	EBPFRingbufSize int

	// Health
	HealthFile string // heartbeat file used by the `-health` check

	// Database
	DBEnabled       bool // persist alerts to TimescaleDB
	DBRetentionDays int  // auto-drop alerts older than this (0 = keep forever)
	DBHost          string
	DBPort          int
	DBName          string
	DBUser          string
	DBPassword      string
	DBSSLMode       string
}

// Load reads all KW_* environment variables and returns a validated Config.
// Returns an error if any required variable is missing or invalid.
func Load() (*Config, error) {
	cfg := &Config{
		// Defaults — can be overridden by env vars
		ServerName:      envOr("KW_SERVER_NAME", "kernelwatch-host"),
		Mode:            envOr("KW_MODE", "alert"),
		AncestryDepth:   5,
		AlertMinSeverity: envOr("KW_ALERT_MIN_SEVERITY", "medium"),
		AlertMaxRate:    10,
		AlertRateWindow: 60,
		AlertFormat:     strings.ToLower(envOr("KW_ALERT_FORMAT", "native")),
		CorrelationEnabled:   envBool("KW_CORRELATION_ENABLED", true),
		CorrelationWindow:    300,
		CorrelationMinStages: 3,
		CorrelationMinScore:  120,
		CorrelationCooldown:  300,
		LogEnabled:      true,
		LogPath:         envOr("KW_LOG_PATH", "/var/log/kernelwatch/alerts.json"),
		LogMaxMB:        50,
		LogMaxBackups:   3,
		HealthFile:      envOr("KW_HEALTH_FILE", "/var/log/kernelwatch/health"),
		APIPort:         8080,
		EBPFRingbufSize: 16 * 1024 * 1024, // 16MB
		DBHost:          envOr("KW_DB_HOST", "localhost"),
		DBPort:          5432,
		DBName:          envOr("KW_DB_NAME", "kernelwatch"),
		DBUser:          envOr("KW_DB_USER", "kernelwatch"),
		DBSSLMode:       envOr("KW_DB_SSL_MODE", "disable"),
	}

	// Container filtering
	cfg.ContainerWhitelist = splitCSV(os.Getenv("KW_CONTAINER_WHITELIST"))
	cfg.ContainerBlacklist = splitCSV(os.Getenv("KW_CONTAINER_BLACKLIST"))

	// Process-lineage detection tuning
	if v, err := envInt("KW_ANCESTRY_DEPTH", 5); err == nil && v > 0 {
		cfg.AncestryDepth = v
	}
	cfg.TrustedParents = splitCSV(os.Getenv("KW_TRUSTED_PARENTS"))
	cfg.NetworkParents = splitCSV(os.Getenv("KW_NETWORK_PARENTS"))
	cfg.DetectionExceptions = splitCSV(os.Getenv("KW_DETECTION_EXCEPTIONS"))

	// Detection ruleset overlays (YAML).
	cfg.RulesFile = os.Getenv("KW_RULES_FILE")
	cfg.RulesDir = os.Getenv("KW_RULES_DIR")

	// Host monitoring (opt-in; default off = container-only behavior).
	cfg.MonitorHost = envBool("KW_MONITOR_HOST", false)
	cfg.HostOpenWatchExtra = splitCSV(os.Getenv("KW_HOST_OPEN_WATCH_EXTRA"))
	cfg.HostExecExclude = splitCSV(os.Getenv("KW_HOST_EXEC_EXCLUDE"))
	cfg.HostTrustedWriters = splitCSV(os.Getenv("KW_HOST_TRUSTED_WRITERS"))
	cfg.HostTrustedParents = splitCSV(os.Getenv("KW_HOST_TRUSTED_PARENTS"))
	cfg.HostDockerClients = splitCSV(os.Getenv("KW_HOST_DOCKER_CLIENTS"))

	// Alert thresholds
	if v, err := envInt("KW_ALERT_MAX_RATE", 10); err == nil {
		cfg.AlertMaxRate = v
	}
	if v, err := envInt("KW_ALERT_RATE_WINDOW", 60); err == nil {
		cfg.AlertRateWindow = v
	}

	// Correlation tuning
	if v, err := envInt("KW_CORRELATION_WINDOW", 300); err == nil && v > 0 {
		cfg.CorrelationWindow = v
	}
	if v, err := envInt("KW_CORRELATION_MIN_STAGES", 3); err == nil && v > 0 {
		cfg.CorrelationMinStages = v
	}
	if v, err := envInt("KW_CORRELATION_MIN_SCORE", 120); err == nil && v > 0 {
		cfg.CorrelationMinScore = v
	}
	if v, err := envInt("KW_CORRELATION_COOLDOWN", 300); err == nil && v >= 0 {
		cfg.CorrelationCooldown = v
	}
	if v, err := envInt("KW_CORRELATION_HOST_MIN_STAGES", 0); err == nil && v > 0 {
		cfg.CorrelationHostMinStages = v
	}
	if v, err := envInt("KW_CORRELATION_HOST_MIN_SCORE", 0); err == nil && v > 0 {
		cfg.CorrelationHostMinScore = v
	}

	// SSH brute-force auth-log tailer.
	cfg.AuthLogEnabled = envBool("KW_AUTHLOG_ENABLED", false)
	cfg.AuthLogPath = envOr("KW_AUTHLOG_PATH", "/var/log/auth.log")
	cfg.SSHBruteThreshold = 5
	cfg.SSHBruteWindow = 60
	if v, err := envInt("KW_SSH_BRUTE_THRESHOLD", 5); err == nil && v > 0 {
		cfg.SSHBruteThreshold = v
	}
	if v, err := envInt("KW_SSH_BRUTE_WINDOW", 60); err == nil && v > 0 {
		cfg.SSHBruteWindow = v
	}

	// Alert destinations
	cfg.LogEnabled = envBool("KW_LOG_ENABLED", true)
	if v, err := envInt("KW_LOG_MAX_MB", 50); err == nil {
		cfg.LogMaxMB = v
	}
	if v, err := envInt("KW_LOG_MAX_BACKUPS", 3); err == nil {
		cfg.LogMaxBackups = v
	}
	cfg.WebhookEnabled = envBool("KW_WEBHOOK_ENABLED", false)
	cfg.WebhookURL = os.Getenv("KW_WEBHOOK_URL")
	cfg.WebhookSecret = os.Getenv("KW_WEBHOOK_SECRET")
	cfg.SlackEnabled = envBool("KW_SLACK_ENABLED", false)
	cfg.SlackWebhookURL = os.Getenv("KW_SLACK_WEBHOOK_URL")
	cfg.SlackChannel = envOr("KW_SLACK_CHANNEL", "#security-alerts")

	// API
	cfg.APIEnabled = envBool("KW_API_ENABLED", false)
	cfg.APIBindAddr = envOr("KW_API_BIND_ADDR", "127.0.0.1")
	if v, err := envInt("KW_API_PORT", 8080); err == nil {
		cfg.APIPort = v
	}
	cfg.APIToken = os.Getenv("KW_API_TOKEN")

	// eBPF
	if v, err := envInt("KW_EBPF_RINGBUF_SIZE", 16*1024*1024); err == nil {
		cfg.EBPFRingbufSize = v
	}

	// Database
	cfg.DBEnabled = envBool("KW_DB_ENABLED", false)
	if v, err := envInt("KW_DB_RETENTION_DAYS", 90); err == nil {
		cfg.DBRetentionDays = v
	}
	cfg.DBPassword = os.Getenv("KW_DB_PASSWORD")
	if v, err := envInt("KW_DB_PORT", 5432); err == nil {
		cfg.DBPort = v
	}

	// Validate
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	validSeverities := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if !validSeverities[c.AlertMinSeverity] {
		return fmt.Errorf("KW_ALERT_MIN_SEVERITY must be one of: low, medium, high, critical (got %q)", c.AlertMinSeverity)
	}
	if c.Mode != "alert" && c.Mode != "monitor" {
		return fmt.Errorf("KW_MODE must be one of: alert, monitor (got %q)", c.Mode)
	}
	if c.AlertFormat != "native" && c.AlertFormat != "ecs" {
		return fmt.Errorf("KW_ALERT_FORMAT must be one of: native, ecs (got %q)", c.AlertFormat)
	}
	if c.DBEnabled {
		if c.DBPassword == "" {
			return fmt.Errorf("KW_DB_PASSWORD is required when KW_DB_ENABLED=true (it must match the database's password)")
		}
		if c.DBPassword == "changeme" {
			return fmt.Errorf("KW_DB_PASSWORD must not be the default 'changeme' — set a strong password")
		}
	}
	if c.APIPort < 1 || c.APIPort > 65535 {
		return fmt.Errorf("KW_API_PORT must be between 1 and 65535 (got %d)", c.APIPort)
	}
	if c.APIEnabled {
		// An exposed, unauthenticated control surface is never acceptable.
		if c.APIToken == "" {
			return fmt.Errorf("KW_API_TOKEN is required when KW_API_ENABLED=true (set a strong random token)")
		}
		if strings.Contains(strings.ToLower(c.APIToken), "changeme") {
			return fmt.Errorf("KW_API_TOKEN must not contain the default placeholder — set a strong random token")
		}
		if len(c.APIToken) < 16 {
			return fmt.Errorf("KW_API_TOKEN is too short (%d chars); use at least 16 random characters", len(c.APIToken))
		}
	}
	if c.RulesFile != "" {
		if fi, err := os.Stat(c.RulesFile); err != nil || fi.IsDir() {
			return fmt.Errorf("KW_RULES_FILE %q is not a readable file", c.RulesFile)
		}
	}
	if c.RulesDir != "" {
		if fi, err := os.Stat(c.RulesDir); err != nil || !fi.IsDir() {
			return fmt.Errorf("KW_RULES_DIR %q is not a directory", c.RulesDir)
		}
	}
	if c.WebhookEnabled && c.WebhookURL == "" {
		return fmt.Errorf("KW_WEBHOOK_URL is required when KW_WEBHOOK_ENABLED=true")
	}
	if c.SlackEnabled && c.SlackWebhookURL == "" {
		return fmt.Errorf("KW_SLACK_WEBHOOK_URL is required when KW_SLACK_ENABLED=true")
	}
	return nil
}

// IsMonitored returns true if the given container name should be monitored,
// applying whitelist and blacklist rules.
func (c *Config) IsMonitored(containerName string) bool {
	// Always skip blacklisted containers
	for _, b := range c.ContainerBlacklist {
		if b != "" && strings.EqualFold(b, containerName) {
			return false
		}
	}
	// If whitelist is set, only monitor those
	if len(c.ContainerWhitelist) > 0 {
		for _, w := range c.ContainerWhitelist {
			if w != "" && strings.EqualFold(w, containerName) {
				return true
			}
		}
		return false
	}
	// No whitelist = monitor everything not blacklisted
	return true
}

// DSN returns the PostgreSQL connection string.
func (c *Config) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		c.DBHost, c.DBPort, c.DBName, c.DBUser, c.DBPassword, c.DBSSLMode,
	)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback, fmt.Errorf("%s must be an integer (got %q)", key, v)
	}
	return n, nil
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
