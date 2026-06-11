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

	// Process-lineage detection tuning
	AncestryDepth       int      // ancestors to resolve per execve (default 5)
	TrustedParents      []string // extra parent comms treated as benign supervisors/schedulers
	NetworkParents      []string // extra parent comms treated as network-facing (attack surface)
	DetectionExceptions []string // suppress matches by image/name/ancestry/argv substring

	// Container filtering
	ContainerWhitelist []string // empty = monitor all
	ContainerBlacklist []string

	// Alert thresholds
	AlertMinSeverity string
	AlertMaxRate     int
	AlertRateWindow  int // seconds

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
	APIPort  int
	APIToken string

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

	// Alert thresholds
	if v, err := envInt("KW_ALERT_MAX_RATE", 10); err == nil {
		cfg.AlertMaxRate = v
	}
	if v, err := envInt("KW_ALERT_RATE_WINDOW", 60); err == nil {
		cfg.AlertRateWindow = v
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
