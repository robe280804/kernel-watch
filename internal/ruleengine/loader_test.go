package ruleengine

import (
	"os"
	"path/filepath"
	"testing"

	"kernelwatch/internal/alerter"
)

func compiledByID(rs []*CompiledRule, id string) *CompiledRule {
	for _, r := range rs {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoadDirLexicalOrder verifies that a directory of overlays is applied in
// lexical order (later files win), that both .yaml and .yml are picked up, and
// that non-YAML files are ignored.
func TestLoadDirLexicalOrder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "01-a.yaml",
		"rules:\n  - id: reverse_shell\n    override: true\n    scope: all\n    condition: \"evt.type = execve\"\n    severity: low\n    reason: first\n")
	writeFile(t, dir, "02-b.yaml",
		"rules:\n  - id: reverse_shell\n    override: true\n    scope: all\n    condition: \"evt.type = execve\"\n    severity: critical\n    reason: second\n")
	writeFile(t, dir, "03-c.yml",
		"rules:\n  - id: my_custom\n    condition: \"evt.type = execve and in_list(proc.exe_base, $shells)\"\n    severity: medium\n    reason: custom\n")
	writeFile(t, dir, "notes.txt", "this is not yaml: [[[ and must be ignored\n")

	eng, err := Load("", dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rs := eng.Rules()

	rev := compiledByID(rs, "reverse_shell")
	if rev == nil {
		t.Fatal("reverse_shell missing after override")
	}
	if rev.severity != alerter.SeverityCritical {
		t.Errorf("reverse_shell severity = %v, want critical (lexically-last override wins)", rev.severity)
	}
	if rev.hasArms {
		t.Error("override should have replaced the rule wholesale (no lineage arms)")
	}
	if compiledByID(rs, "my_custom") == nil {
		t.Error("my_custom from the .yml overlay was not loaded")
	}
}

// TestLoadFileOverrideAndNew verifies a single rulesFile overlay can override a
// default rule and add a new one without disturbing the rest.
func TestLoadFileOverrideAndNew(t *testing.T) {
	dir := t.TempDir()
	file := writeFile(t, dir, "ops.yaml",
		"rules:\n"+
			"  - id: shell_in_container\n    override: true\n    scope: container\n    condition: \"evt.type = execve\"\n    severity: low\n    reason: downgraded\n"+
			"  - id: extra_rule\n    condition: \"evt.type = execve and in_list(proc.exe_base, $shells)\"\n    severity: medium\n    reason: extra\n")

	base, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	eng, err := Load(file, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// One new rule => exactly one more than the default ruleset.
	if got, want := len(eng.Rules()), len(base.Rules())+1; got != want {
		t.Errorf("rule count = %d, want %d", got, want)
	}
	shell := compiledByID(eng.Rules(), "shell_in_container")
	if shell == nil || shell.severity != alerter.SeverityLow {
		t.Errorf("shell_in_container override not applied: %#v", shell)
	}
	if compiledByID(eng.Rules(), "extra_rule") == nil {
		t.Error("extra_rule was not added")
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name string
		file string
		body string // written to file when non-empty
	}{
		{"malformed yaml", "bad.yaml", "rules:\n  - id: x\n    condition: [unterminated\n"},
		{"unknown key", "unknown.yaml", "rules:\n  - id: x\n    bogus: nope\n"},
		{"duplicate id no override", "dup.yaml",
			"rules:\n  - id: reverse_shell\n    condition: \"evt.type = execve\"\n    severity: low\n    reason: dup\n"},
		{"append to unknown rule", "append.yaml",
			"rules:\n  - id: does_not_exist\n    append: true\n    tags: [extra]\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeFile(t, dir, tc.file, tc.body)
			if _, err := Load(path, ""); err == nil {
				t.Errorf("Load(%s) = nil error, want error", tc.name)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		if _, err := Load(filepath.Join(dir, "nope.yaml"), ""); err == nil {
			t.Error("Load of a missing file should error")
		}
	})
	t.Run("missing dir", func(t *testing.T) {
		if _, err := Load("", filepath.Join(dir, "no-such-dir")); err == nil {
			t.Error("Load of a missing dir should error")
		}
	})
}
