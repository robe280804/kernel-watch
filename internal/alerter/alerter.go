package alerter

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"containersentry/internal/config"
)

// Severity levels for alerts.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Alert represents a security event detected by ContainerSentry.
type Alert struct {
	ID          string    `json:"id"`
	ServerName  string    `json:"server_name"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    Severity  `json:"severity"`
	ContainerID string    `json:"container_id"`
	ContainerName string  `json:"container_name"`
	ImageName   string    `json:"image_name"`
	Syscall     string    `json:"syscall,omitempty"`
	PID         uint32    `json:"pid"`
	ProcessName string    `json:"process_name"`
	Reason      string    `json:"reason"`
	Details     map[string]any `json:"details,omitempty"`
	// MITRE ATT&CK mapping (populated by detector)
	MITRETTP    string `json:"mitre_ttp,omitempty"`
	MITRETactic string `json:"mitre_tactic,omitempty"`
}

// Alerter dispatches alerts to configured destinations.
type Alerter struct {
	cfg        *config.Config
	logFile    *os.File
	mu         sync.Mutex
	httpClient *http.Client

	// Rate limiting: track alert count per container in sliding window
	rateMu   sync.Mutex
	rateMap  map[string][]time.Time // containerID → timestamps
}

// New creates an Alerter from config.
func New(cfg *config.Config) (*Alerter, error) {
	a := &Alerter{
		cfg:     cfg,
		rateMap: make(map[string][]time.Time),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}

	if cfg.LogEnabled {
		if err := os.MkdirAll(filepath.Dir(cfg.LogPath), 0755); err != nil {
			return nil, fmt.Errorf("create log dir: %w", err)
		}
		f, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		a.logFile = f
	}

	return a, nil
}

// Send dispatches an alert to all configured destinations.
// It applies severity filtering and rate limiting before dispatching.
func (a *Alerter) Send(alert *Alert) {
	// Severity filter
	if severityRank[alert.Severity] < severityRank[Severity(a.cfg.AlertMinSeverity)] {
		return
	}

	// Rate limiting per container
	if a.isRateLimited(alert.ContainerID) {
		slog.Debug("alert rate limited", "container", alert.ContainerName)
		return
	}

	alert.ServerName = a.cfg.ServerName
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}

	if a.cfg.LogEnabled {
		a.writeLog(alert)
	}
	if a.cfg.WebhookEnabled {
		go a.sendWebhook(alert)
	}
	if a.cfg.SlackEnabled {
		go a.sendSlack(alert)
	}
}

// Close flushes and closes open resources.
func (a *Alerter) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.logFile != nil {
		a.logFile.Close()
	}
}

// ── Log destination ───────────────────────────────────────────────────────────

func (a *Alerter) writeLog(alert *Alert) {
	data, err := json.Marshal(alert)
	if err != nil {
		slog.Error("marshal alert", "err", err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.logFile != nil {
		a.logFile.Write(data)
		a.logFile.WriteString("\n")
	}
	// Also print to stdout with structured logging
	slog.Warn("security alert",
		"severity", alert.Severity,
		"container", alert.ContainerName,
		"reason", alert.Reason,
		"syscall", alert.Syscall,
		"pid", alert.PID,
	)
}

// ── Webhook destination ───────────────────────────────────────────────────────

func (a *Alerter) sendWebhook(alert *Alert) {
	data, err := json.Marshal(alert)
	if err != nil {
		slog.Error("webhook marshal", "err", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, a.cfg.WebhookURL, bytes.NewReader(data))
	if err != nil {
		slog.Error("webhook request", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ContainerSentry/1.0")

	// HMAC-SHA256 signature for webhook verification
	if a.cfg.WebhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(a.cfg.WebhookSecret))
		mac.Write(data)
		req.Header.Set("X-ContainerSentry-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		slog.Error("webhook send", "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		slog.Error("webhook response", "status", resp.StatusCode)
	}
}

// ── Slack destination ─────────────────────────────────────────────────────────

type slackPayload struct {
	Channel  string       `json:"channel"`
	Username string       `json:"username"`
	IconEmoji string      `json:"icon_emoji"`
	Blocks   []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type string     `json:"type"`
	Text *slackText `json:"text,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (a *Alerter) sendSlack(alert *Alert) {
	emoji := map[Severity]string{
		SeverityLow:      ":information_source:",
		SeverityMedium:   ":warning:",
		SeverityHigh:     ":rotating_light:",
		SeverityCritical: ":skull:",
	}[alert.Severity]

	text := fmt.Sprintf("%s *[%s]* %s\n>*Server:* %s | *Container:* `%s` (`%s`)\n>*Reason:* %s\n>*Process:* `%s` (PID %d)",
		emoji,
		strings.ToUpper(string(alert.Severity)),
		alert.Reason,
		alert.ServerName,
		alert.ContainerName,
		alert.ImageName,
		alert.Reason,
		alert.ProcessName,
		alert.PID,
	)

	if alert.MITRETTP != "" {
		text += fmt.Sprintf("\n>*MITRE:* %s — %s", alert.MITRETTP, alert.MITRETactic)
	}

	payload := slackPayload{
		Channel:   a.cfg.SlackChannel,
		Username:  "ContainerSentry",
		IconEmoji: ":shield:",
		Blocks: []slackBlock{
			{Type: "section", Text: &slackText{Type: "mrkdwn", Text: text}},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		slog.Error("slack marshal", "err", err)
		return
	}

	resp, err := a.httpClient.Post(a.cfg.SlackWebhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		slog.Error("slack send", "err", err)
		return
	}
	defer resp.Body.Close()
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

func (a *Alerter) isRateLimited(containerID string) bool {
	a.rateMu.Lock()
	defer a.rateMu.Unlock()

	window := time.Duration(a.cfg.AlertRateWindow) * time.Second
	cutoff := time.Now().Add(-window)

	// Evict old timestamps
	ts := a.rateMap[containerID]
	fresh := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}

	if len(fresh) >= a.cfg.AlertMaxRate {
		a.rateMap[containerID] = fresh
		return true
	}

	a.rateMap[containerID] = append(fresh, time.Now())
	return false
}
