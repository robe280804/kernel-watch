package suppress

import "testing"

func tgt(ruleID, container, process, haystack string) Target {
	return Target{RuleID: ruleID, ContainerName: container, ProcessName: process, Haystack: haystack}
}

func TestEmptyRuleNeverMatches(t *testing.T) {
	var r Rule
	if !r.Empty() {
		t.Fatal("zero-value rule should be Empty")
	}
	if r.Match(tgt("network_tool", "app", "curl", "anything goes here")) {
		t.Fatal("empty rule must never match (would silence everything)")
	}
}

func TestScopeAndHostnameAreNarrowingOnly(t *testing.T) {
	// A rule whose only criteria are scope/hostname must be Empty — otherwise it
	// could blanket-silence an entire scope or host.
	if !(Rule{Scope: "host"}).Empty() {
		t.Fatal("scope-only rule must be Empty (no blanket host-silencing)")
	}
	if !(Rule{Hostname: "web-01"}).Empty() {
		t.Fatal("hostname-only rule must be Empty")
	}
	if (Rule{RuleID: "host_tmp_exec", Scope: "host"}).Empty() {
		t.Fatal("a primary criterion + scope is NOT empty")
	}
}

func TestRuleCriteriaAreANDed(t *testing.T) {
	r := Rule{RuleID: "network_tool", ContainerName: "app"}
	if !r.Match(tgt("network_tool", "app", "curl", "app curl http")) {
		t.Fatal("matching rule+container should suppress")
	}
	if r.Match(tgt("network_tool", "other", "curl", "")) {
		t.Fatal("container mismatch must not suppress")
	}
	if r.Match(tgt("shell_in_container", "app", "bash", "")) {
		t.Fatal("rule id mismatch must not suppress")
	}
}

func TestScopeAndHostnameNarrow(t *testing.T) {
	// Suppress host_tmp_exec only on host web-01.
	r := Rule{RuleID: "host_tmp_exec", Scope: "host", Hostname: "web-01"}
	hit := Target{RuleID: "host_tmp_exec", Scope: "host", Hostname: "web-01"}
	if !r.Match(hit) {
		t.Fatal("rule should match its exact scope+host target")
	}
	other := hit
	other.Hostname = "web-02"
	if r.Match(other) {
		t.Fatal("a suppression for one host must not silence another host in the fleet")
	}
	cont := hit
	cont.Scope = "container"
	if r.Match(cont) {
		t.Fatal("scope mismatch must not suppress")
	}
}

func TestSubstrCaseInsensitive(t *testing.T) {
	r := Rule{Substr: "Backup-Image"}
	if !r.Match(tgt("network_tool", "c", "curl", "registry/backup-image:1.0 curl ...")) {
		t.Fatal("substr should match case-insensitively against the haystack")
	}
	if r.Match(tgt("network_tool", "c", "curl", "registry/app:1.0")) {
		t.Fatal("non-matching substr must not suppress")
	}
}

func TestSetSuppresses(t *testing.T) {
	s := Set{
		{ContainerName: "ci-runner"},
		{RuleID: "package_manager", ProcessName: "apt-get"},
	}
	if !s.Suppresses(tgt("anything", "ci-runner", "x", "")) {
		t.Fatal("first rule should match ci-runner")
	}
	if !s.Suppresses(tgt("package_manager", "app", "apt-get", "")) {
		t.Fatal("second rule should match apt-get package_manager")
	}
	if s.Suppresses(tgt("shell_in_container", "app", "bash", "")) {
		t.Fatal("no rule should match this alert")
	}
}
