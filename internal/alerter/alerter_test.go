package alerter

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kernelwatch/internal/config"
)

func TestEscapeSlackNeutralizesInjection(t *testing.T) {
	// An attacker-controlled command line trying to break out of the code span
	// and inject Slack formatting / a forged quote line.
	in := "bash -c `id` <http://evil|click> & done\nFAKE: all clear"
	out := escapeSlack(in)
	for _, bad := range []string{"`", "\n", "\r"} {
		if strings.Contains(out, bad) {
			t.Fatalf("escapeSlack left %q in output: %q", bad, out)
		}
	}
	if !strings.Contains(out, "&amp;") || !strings.Contains(out, "&lt;") || !strings.Contains(out, "&gt;") {
		t.Fatalf("escapeSlack did not HTML-escape angle brackets/ampersand: %q", out)
	}
}

func TestKillChainRank(t *testing.T) {
	if KillChainRank("Execution") >= KillChainRank("Exfiltration") {
		t.Fatal("Execution must rank earlier than Exfiltration in the kill chain")
	}
	if KillChainRank("") != 0 || KillChainRank("Nonsense") != 0 {
		t.Fatal("unknown/empty tactic should rank 0")
	}
	if KillChainRank("credential access") != KillChainRank("Credential Access") {
		t.Fatal("rank lookup must be case-insensitive")
	}
}

func TestECSMapping(t *testing.T) {
	a := &Alert{
		ID:            "abc",
		RuleID:        "shell_in_container",
		ServerName:    "host1",
		Timestamp:     time.Unix(1700000000, 0),
		Severity:      SeverityCritical,
		ContainerName: "app",
		ImageName:     "app:latest",
		Syscall:       "execve",
		PID:           1234,
		ProcessName:   "bash",
		Reason:        "interactive shell spawned by network-facing service",
		MITRETTP:      "T1059",
		MITRETactic:   "Execution",
		Tags:          []string{"container", "shell"},
		KillChainPhase: "Execution",
	}
	m := a.ECS()

	ev, ok := m["event"].(map[string]any)
	if !ok {
		t.Fatal("ecs output missing event object")
	}
	if ev["severity"].(int) != 99 {
		t.Fatalf("critical should map to ECS severity 99, got %v", ev["severity"])
	}
	if ev["action"] != "shell_in_container" {
		t.Fatalf("event.action should be the rule id, got %v", ev["action"])
	}
	threat := m["threat"].(map[string]any)
	if threat["framework"] != "MITRE ATT&CK" {
		t.Fatalf("threat.framework wrong: %v", threat)
	}

	// Must be valid JSON.
	if _, err := json.Marshal(m); err != nil {
		t.Fatalf("ecs output is not JSON-serializable: %v", err)
	}
}

func newLoggingAlerter(t *testing.T, minSeverity string) (*Alerter, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "alerts.json")
	cfg := &config.Config{
		ServerName:       "test",
		Mode:             "alert",
		AlertMinSeverity: minSeverity,
		AlertMaxRate:     10,
		AlertRateWindow:  60,
		LogEnabled:       true,
		LogPath:          logPath,
		LogMaxMB:         50,
		LogMaxBackups:    3,
		AlertFormat:      "native",
	}
	a, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("new alerter: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	return a, logPath
}

func logLineCount(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}

func TestIncidentBypassesSeverityFilter(t *testing.T) {
	a, logPath := newLoggingAlerter(t, "critical")

	// A high-severity single finding is below the critical threshold → dropped.
	a.Send(&Alert{Severity: SeverityHigh, ContainerID: "c", Reason: "single finding"})
	if got := logLineCount(t, logPath); got != 0 {
		t.Fatalf("high finding should be filtered below critical threshold, logged %d", got)
	}

	// A high-severity correlated incident must still be logged (bypass).
	a.Send(&Alert{Severity: SeverityHigh, ContainerID: "c", Reason: "attack chain", Tags: []string{TagAttackChain}})
	if got := logLineCount(t, logPath); got != 1 {
		t.Fatalf("incident should bypass the severity filter, logged %d", got)
	}
}

func TestIncidentBypassesRateLimit(t *testing.T) {
	a, logPath := newLoggingAlerter(t, "low")
	a.cfg.AlertMaxRate = 2

	// Exhaust the per-container rate budget with ordinary findings.
	for i := 0; i < 5; i++ {
		a.Send(&Alert{Severity: SeverityHigh, ContainerID: "c", Reason: "noise"})
	}
	noisy := logLineCount(t, logPath)
	if noisy > 2 {
		t.Fatalf("ordinary findings should be rate-limited to 2, logged %d", noisy)
	}

	// The incident for the same (now rate-limited) container must still go out.
	a.Send(&Alert{Severity: SeverityCritical, ContainerID: "c", Reason: "chain", Tags: []string{TagAttackChain}})
	if got := logLineCount(t, logPath); got != noisy+1 {
		t.Fatalf("incident should bypass rate limiting: before=%d after=%d", noisy, logLineCount(t, logPath))
	}
}
