package logtail

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"kernelwatch/internal/alerter"
)

// Config tunes the SSH brute-force tailer.
type Config struct {
	Path         string        // auth log path (e.g. /var/log/auth.log or /hostlog/auth.log)
	Threshold    int           // failed attempts per source IP within the window
	Window       time.Duration // sliding window
	ServerName   string        // host identity stamped on synthesized alerts
	PollInterval time.Duration // how often to poll the file for new data (default 1s)
}

// Tailer follows an auth log and emits host-scope ssh_bruteforce alerts when a
// source IP crosses the failure threshold inside the window.
type Tailer struct {
	cfg  Config
	tr   *tracker
	emit func(*alerter.Alert)
}

// New builds a Tailer. emit is the sink for synthesized alerts (typically
// alerter.Send) and must be safe to call from the tailer goroutine.
func New(cfg Config, emit func(*alerter.Alert)) *Tailer {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	return &Tailer{cfg: cfg, tr: newTracker(cfg.Threshold, cfg.Window), emit: emit}
}

// Run tails the file until ctx is cancelled. It starts at the END of the file
// (so it never replays history on startup), polls for appended data, and
// re-opens the file on rotation/truncation. Missing files are tolerated: it
// retries until the file appears or ctx is done.
func (t *Tailer) Run(ctx context.Context) {
	slog.Info("ssh brute-force tailer started",
		"path", t.cfg.Path, "threshold", t.cfg.Threshold, "window", t.cfg.Window)

	var (
		f      *os.File
		reader *bufio.Reader
		offset int64
	)
	openAtEnd := func() {
		var err error
		f, err = os.Open(t.cfg.Path)
		if err != nil {
			f = nil
			return
		}
		if fi, err := f.Stat(); err == nil {
			offset, _ = f.Seek(fi.Size(), io.SeekStart) // start at EOF
		}
		reader = bufio.NewReader(f)
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	ticker := time.NewTicker(t.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if f == nil {
			openAtEnd()
			if f == nil {
				continue // file not present yet
			}
		}

		// Detect rotation/truncation: if the file shrank below our offset, the
		// log was rotated — reopen from the start of the new file.
		if fi, err := os.Stat(t.cfg.Path); err == nil && fi.Size() < offset {
			f.Close()
			f, _ = os.Open(t.cfg.Path)
			if f == nil {
				continue
			}
			reader = bufio.NewReader(f)
			offset = 0
		}

		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				offset += int64(len(line))
				if line[len(line)-1] == '\n' {
					if a := t.handleLine(line, time.Now()); a != nil {
						t.emit(a)
					}
				} else {
					// Partial line (no newline yet): rewind so we re-read it whole
					// on the next poll.
					offset -= int64(len(line))
					_, _ = f.Seek(offset, io.SeekStart)
					reader = bufio.NewReader(f)
					break
				}
			}
			if err != nil {
				break // EOF or read error — wait for the next tick
			}
		}
	}
}

// handleLine parses one log line and, if it crosses the brute-force threshold,
// returns the synthesized alert (nil otherwise). Separated from the IO loop so
// it is unit-testable.
func (t *Tailer) handleLine(line string, now time.Time) *alerter.Alert {
	ip, ok := FailedAuthIP(line)
	if !ok {
		return nil
	}
	n, fired := t.tr.add(ip, now)
	if !fired {
		return nil
	}
	return &alerter.Alert{
		RuleID:         "ssh_bruteforce",
		Scope:          alerter.ScopeHost,
		Severity:       alerter.SeverityHigh,
		Reason:         fmt.Sprintf("SSH brute-force: %d failed authentications from %s within %s", n, ip, t.cfg.Window),
		MITRETTP:       "T1110.001",
		MITRETactic:    "Credential Access",
		KillChainPhase: "Credential Access",
		Tags:           []string{"host", "ssh", "brute-force"},
		ProcessName:    "sshd",
		ServerName:     t.cfg.ServerName,
		Timestamp:      now,
		Details: map[string]any{
			"source_ip":      ip,
			"attempts":       n,
			"window_seconds": int(t.cfg.Window.Seconds()),
		},
	}
}
