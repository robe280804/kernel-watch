package ruleengine

import (
	"testing"

	"kernelwatch/internal/collector"
)

// fakeLP is a stand-in lineage provider for engine/DSL tests (the real one lives
// in the detector package and is exercised by detector_test.go).
type fakeLP struct{}

func (fakeLP) Classify(anc []string, host bool) Lineage {
	for _, a := range anc {
		switch a {
		case "nginx", "php-fpm", "node":
			return LineageNetwork
		}
	}
	for _, a := range anc {
		switch a {
		case "sshd", "tmux", "login":
			return LineageInteractive
		}
	}
	for _, a := range anc {
		switch a {
		case "cron", "systemd", "containerd-shim":
			return LineageTrusted
		}
	}
	return LineageUnknown
}

func (fakeLP) TrustedWriter(chain []string) bool {
	for _, a := range chain {
		switch a {
		case "dpkg", "apt", "systemd", "dockerd", "systemd-udevd", "rsyslogd":
			return true
		}
	}
	return false
}

func (fakeLP) NetworkParent(anc []string) string {
	for _, a := range anc {
		switch a {
		case "nginx", "php-fpm", "node":
			return a
		}
	}
	return ""
}

func (fakeLP) IsDockerClient(comm string) bool { return comm == "dockerd" || comm == "docker" }

func evalCond(t *testing.T, cond string, lists map[string][]string, e collector.Event, scope Scope) bool {
	t.Helper()
	pr, err := compileCondition(cond, lists)
	if err != nil {
		t.Fatalf("compile %q: %v", cond, err)
	}
	return pr(newEvalCtx(&e, fakeLP{}, scope))
}

func TestLexerBasics(t *testing.T) {
	toks, err := lex(`evt.type = execve and proc.request in [4, 0x10] and not is_trusted_writer`)
	if err != nil {
		t.Fatal(err)
	}
	if toks[len(toks)-1].kind != tEOF {
		t.Fatal("missing EOF")
	}
	// hex literal
	got := false
	for _, tk := range toks {
		if tk.kind == tInt && tk.text == "0x10" {
			got = true
		}
	}
	if !got {
		t.Fatal("hex int not lexed")
	}
}

func TestComparisons(t *testing.T) {
	lists := map[string][]string{"shells": {"bash", "sh"}}
	ex := collector.Event{Type: collector.EventExecve, Filename: "/bin/bash", CmdLine: "bash -c x"}

	cases := []struct {
		cond string
		want bool
	}{
		{`evt.type = execve`, true},
		{`evt.type = open`, false},
		{`evt.type != open`, true},
		{`in_list(proc.exe_base, $shells)`, true},
		{`proc.exe_base in $shells`, true},
		{`proc.cmdline contains "-c"`, true},
		{`proc.exe_path startswith "/bin"`, true},
		{`proc.cmdline != ""`, true},
		{`evt.type = execve and not evt.type = open`, true},
		{`evt.type = open or evt.type = execve`, true},
	}
	for _, c := range cases {
		if got := evalCond(t, c.cond, lists, ex, ScopeContainer); got != c.want {
			t.Errorf("%q = %v, want %v", c.cond, got, c.want)
		}
	}
}

func TestBitmaskAndIntIn(t *testing.T) {
	ep := collector.Event{Type: collector.EventPtrace, Arg1: 16}
	if !evalCond(t, `ptrace.request in [4, 5, 16]`, nil, ep, ScopeContainer) {
		t.Fatal("ptrace.request in list should match 16")
	}
	if evalCond(t, `ptrace.request in [4, 5]`, nil, ep, ScopeContainer) {
		t.Fatal("16 should not be in [4,5]")
	}
	eo := collector.Event{Type: collector.EventOpen, Arg1: 0x1 | 0x40}
	if !evalCond(t, `evt.is_open_write`, nil, eo, ScopeContainer) {
		t.Fatal("O_WRONLY|O_CREAT should be a write open")
	}
}

func TestUnknownListAndFieldRejected(t *testing.T) {
	if _, err := compileCondition(`in_list(proc.exe_base, $missing)`, nil); err == nil {
		t.Fatal("expected error for unknown $list")
	}
	if _, err := compileCondition(`proc.bogus = x`, nil); err == nil {
		t.Fatal("expected error for unknown field")
	}
	if _, err := compileCondition(`evt.type =`, nil); err == nil {
		t.Fatal("expected error for missing operand")
	}
}

func TestMacroCycleDetected(t *testing.T) {
	_, err := resolveMacros(map[string]string{
		"a": "b and evt.type = execve",
		"b": "a or evt.type = open",
	})
	if err == nil {
		t.Fatal("expected a macro cycle error")
	}
}

func TestMacroExpansion(t *testing.T) {
	resolved, err := resolveMacros(map[string]string{
		"is_execve":    "evt.type = execve",
		"spawns_shell": "is_execve and in_list(proc.exe_base, $shells)",
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := applyMacros("spawns_shell", resolved)
	if err != nil {
		t.Fatal(err)
	}
	// The macro reference must be gone and the field expression present.
	if !contains(out, "evt.type = execve") || !contains(out, "in_list(proc.exe_base, $shells)") {
		t.Fatalf("unexpected expansion: %q", out)
	}
	if contains(out, "spawns_shell") || contains(out, "is_execve") {
		t.Fatalf("macro names should be fully expanded: %q", out)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && indexOf(s, sub) >= 0 }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
