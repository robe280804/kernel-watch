package alerter

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
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

	"kernelwatch/internal/config"
)

// deliveryAttempts is how many times webhook/Slack delivery is retried before
// giving up (the alert is still in the log and DB).
const deliveryAttempts = 3

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

// Alert represents a security event detected by KernelWatch.
type Alert struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"rule_id,omitempty"`
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
	// Process lineage + command line (populated by detector for execve events)
	ParentName string   `json:"parent_name,omitempty"`
	Ancestry   []string `json:"ancestry,omitempty"`
	CmdLine    string   `json:"cmdline,omitempty"`
	// MITRE ATT&CK mapping + categorization (populated by detector)
	MITRETTP    string   `json:"mitre_ttp,omitempty"`
	MITRETactic string   `json:"mitre_tactic,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// AlertSink is an optional persistence destination (e.g. TimescaleDB). It is
// defined here so the alerter does not import the storage package (avoiding an
// import cycle); the concrete store is injected by main.
type AlertSink interface {
	Save(*Alert)
}

// Alerter dispatches alerts to configured destinations.
type Alerter struct {
	cfg        *config.Config
	logFile    *os.File
	logBytes   int64 // current size of the open log file (for rotation)
	sink       AlertSink // optional; nil when persistence is disabled
	mu         sync.Mutex
	httpClient *http.Client

	// Rate limiting: track alert count per container in sliding window
	rateMu   sync.Mutex
	rateMap  map[string][]time.Time // containerID → timestamps
}

// New creates an Alerter from config. sink may be nil (persistence disabled).
func New(cfg *config.Config, sink AlertSink) (*Alerter, error) {
	a := &Alerter{
		cfg:     cfg,
		sink:    sink,
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
		if fi, err := f.Stat(); err == nil {
			a.logBytes = fi.Size()
		}
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
	if alert.ID == "" {
		alert.ID = genID()
	}

	if a.cfg.LogEnabled {
		a.writeLog(alert)
	}

	// Persist to the database (best-effort, non-blocking). Done in both alert
	// and monitor modes so the history is complete during a tuning period.
	if a.sink != nil {
		a.sink.Save(alert)
	}

	// Monitor (dry-run) mode: evaluate + log + persist, but never dispatch to
	// external destinations — used for safe rollout and rule tuning.
	if a.cfg.Mode == "monitor" {
		return
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
		n, _ := a.logFile.Write(data)
		m, _ := a.logFile.WriteString("\n")
		a.logBytes += int64(n + m)
		a.rotateIfNeeded()
	}
	// Also print to stdout with structured logging
	slog.Warn("security alert",
		"severity", alert.Severity,
		"container", alert.ContainerName,
		"image", alert.ImageName,
		"reason", alert.Reason,
		"process", alert.ProcessName,
		"parent", alert.ParentName,
		"cmdline", alert.CmdLine,
		"syscall", alert.Syscall,
		"pid", alert.PID,
		"mitre", alert.MITRETTP,
	)
}

// rotateIfNeeded rolls the log file over when it exceeds KW_LOG_MAX_MB, keeping
// KW_LOG_MAX_BACKUPS numbered backups (alerts.json.1 … .N). Caller must hold mu.
func (a *Alerter) rotateIfNeeded() {
	maxBytes := int64(a.cfg.LogMaxMB) * 1024 * 1024
	if maxBytes <= 0 || a.logBytes < maxBytes || a.logFile == nil {
		return
	}
	path := a.cfg.LogPath
	a.logFile.Close()

	// Shift backups: .(N-1) → .N, dropping the oldest.
	if a.cfg.LogMaxBackups > 0 {
		_ = os.Remove(fmt.Sprintf("%s.%d", path, a.cfg.LogMaxBackups))
		for i := a.cfg.LogMaxBackups - 1; i >= 1; i-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
		}
		_ = os.Rename(path, path+".1")
	} else {
		_ = os.Remove(path) // no backups kept — just truncate by removing
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		slog.Error("log rotate: reopen failed", "err", err)
		a.logFile = nil
		return
	}
	a.logFile = f
	a.logBytes = 0
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
	req.Header.Set("User-Agent", "KernelWatch/1.0")

	// HMAC-SHA256 signature for webhook verification
	if a.cfg.WebhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(a.cfg.WebhookSecret))
		mac.Write(data)
		req.Header.Set("X-KernelWatch-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	if err := a.postWithRetry(a.cfg.WebhookURL, data, req.Header); err != nil {
		slog.Error("webhook delivery failed after retries", "alert_id", alert.ID, "err", err)
	}
}

// postWithRetry POSTs body with the given headers, retrying with backoff on
// transport errors or 5xx/429 responses. 4xx (other than 429) are not retried.
func (a *Alerter) postWithRetry(url string, body []byte, header http.Header) error {
	var lastErr error
	for attempt := 0; attempt < deliveryAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err // non-retryable (bad URL)
		}
		if header != nil {
			req.Header = header.Clone()
		}
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := a.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			return nil
		}
		lastErr = fmt.Errorf("status %d", resp.StatusCode)
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return lastErr // client error — don't retry
		}
	}
	return lastErr
}

// genID returns a random 128-bit hex identifier for an alert.
func genID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("ts-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
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

	text := fmt.Sprintf("%s *[%s]* %s\n>*Server:* %s | *Container:* `%s` (`%s`)\n>*Process:* `%s` (PID %d)",
		emoji,
		strings.ToUpper(string(alert.Severity)),
		alert.Reason,
		alert.ServerName,
		alert.ContainerName,
		alert.ImageName,
		alert.ProcessName,
		alert.PID,
	)

	if alert.ParentName != "" {
		text += fmt.Sprintf("\n>*Parent:* `%s`", alert.ParentName)
	}
	if alert.CmdLine != "" {
		text += fmt.Sprintf("\n>*Command:* `%s`", alert.CmdLine)
	}
	if alert.MITRETTP != "" {
		text += fmt.Sprintf("\n>*MITRE:* %s — %s", alert.MITRETTP, alert.MITRETactic)
	}

	payload := slackPayload{
		Channel:   a.cfg.SlackChannel,
		Username:  "KernelWatch",
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

	if err := a.postWithRetry(a.cfg.SlackWebhookURL, data, nil); err != nil {
		slog.Error("slack delivery failed after retries", "alert_id", alert.ID, "err", err)
	}
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
