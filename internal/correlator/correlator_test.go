package correlator

import (
	"testing"
	"time"

	"kernelwatch/internal/alerter"
)

func testConfig() Config {
	return Config{Window: 5 * time.Minute, MinStages: 3, MinScore: 120, Cooldown: 0}
}

func finding(containerID, tactic string, sev alerter.Severity, at time.Time) *alerter.Alert {
	return &alerter.Alert{
		RuleID:        "r_" + tactic,
		Severity:      sev,
		MITRETactic:   tactic,
		ContainerID:   containerID,
		ContainerName: "app",
		Timestamp:     at,
		Reason:        tactic + " activity",
	}
}

func TestSingleFindingNoIncident(t *testing.T) {
	c := New(testConfig())
	if inc := c.Observe(finding("c1", "Execution", alerter.SeverityHigh, time.Unix(1000, 0))); inc != nil {
		t.Fatalf("a lone finding must not raise an incident, got %v", inc.Reason)
	}
}

func TestDistinctStagesRaiseIncident(t *testing.T) {
	c := New(testConfig())
	t0 := time.Unix(1000, 0)
	c.Observe(finding("c1", "Execution", alerter.SeverityHigh, t0))
	c.Observe(finding("c1", "Discovery", alerter.SeverityMedium, t0.Add(time.Second)))
	inc := c.Observe(finding("c1", "Credential Access", alerter.SeverityHigh, t0.Add(2*time.Second)))

	if inc == nil {
		t.Fatal("3 distinct kill-chain stages should raise an incident")
	}
	if !inc.IsIncident() || inc.RuleID != IncidentRuleID {
		t.Fatalf("incident not tagged correctly: %+v", inc.Tags)
	}
	if inc.RiskScore != 125 {
		t.Fatalf("expected risk 125 (50+25+50), got %d", inc.RiskScore)
	}
	if inc.Severity != alerter.SeverityHigh {
		t.Fatalf("3 stages / risk 125 should be High, got %s", inc.Severity)
	}
	stages, _ := inc.Details["stages"].([]string)
	if len(stages) != 3 || stages[0] != "Execution" {
		t.Fatalf("stages should be kill-chain ordered, got %v", stages)
	}
}

func TestNoDuplicateIncidentForSameStageSet(t *testing.T) {
	c := New(testConfig())
	t0 := time.Unix(1000, 0)
	c.Observe(finding("c1", "Execution", alerter.SeverityHigh, t0))
	c.Observe(finding("c1", "Discovery", alerter.SeverityMedium, t0.Add(time.Second)))
	if inc := c.Observe(finding("c1", "Credential Access", alerter.SeverityHigh, t0.Add(2*time.Second))); inc == nil {
		t.Fatal("expected first incident")
	}
	// More activity in the SAME stages must not re-alert.
	if inc := c.Observe(finding("c1", "Credential Access", alerter.SeverityHigh, t0.Add(3*time.Second))); inc != nil {
		t.Fatalf("same stage-set must not re-emit, got %v", inc.Reason)
	}
}

func TestNewStageEscalates(t *testing.T) {
	c := New(testConfig())
	t0 := time.Unix(1000, 0)
	c.Observe(finding("c1", "Execution", alerter.SeverityHigh, t0))
	c.Observe(finding("c1", "Discovery", alerter.SeverityMedium, t0.Add(time.Second)))
	c.Observe(finding("c1", "Credential Access", alerter.SeverityHigh, t0.Add(2*time.Second)))

	// A 4th distinct stage joins the chain → escalated re-emit, now Critical.
	inc := c.Observe(finding("c1", "Persistence", alerter.SeverityHigh, t0.Add(3*time.Second)))
	if inc == nil {
		t.Fatal("a new kill-chain stage should escalate and re-emit")
	}
	if inc.Severity != alerter.SeverityCritical {
		t.Fatalf("4 stages should escalate to Critical, got %s", inc.Severity)
	}
}

func TestScoreThresholdRaisesIncident(t *testing.T) {
	// Stages never reach MinStages, but accumulated risk crosses MinScore.
	c := New(Config{Window: time.Minute, MinStages: 99, MinScore: 120, Cooldown: 0})
	t0 := time.Unix(1000, 0)
	c.Observe(finding("c1", "Execution", alerter.SeverityCritical, t0)) // 100
	if inc := c.Observe(finding("c1", "Execution", alerter.SeverityHigh, t0.Add(time.Second))); inc == nil {
		t.Fatal("risk 150 should cross the score threshold even with one stage")
	}
}

func TestWindowEviction(t *testing.T) {
	c := New(Config{Window: 30 * time.Second, MinStages: 3, MinScore: 9999, Cooldown: 0})
	t0 := time.Unix(1000, 0)
	c.Observe(finding("c1", "Execution", alerter.SeverityHigh, t0))
	c.Observe(finding("c1", "Discovery", alerter.SeverityHigh, t0.Add(time.Second)))
	// Third stage arrives long after the first two have aged out of the window.
	if inc := c.Observe(finding("c1", "Persistence", alerter.SeverityHigh, t0.Add(5*time.Minute))); inc != nil {
		t.Fatalf("stages outside the window must not correlate, got %v", inc.Reason)
	}
}

func TestIncidentsAreNotRecorrelated(t *testing.T) {
	c := New(testConfig())
	inc := &alerter.Alert{RuleID: IncidentRuleID, ContainerID: "c1", Tags: []string{alerter.TagAttackChain}}
	if got := c.Observe(inc); got != nil {
		t.Fatal("an incident must not feed the correlator")
	}
}

func hostFinding(server, tactic string, sev alerter.Severity, at time.Time) *alerter.Alert {
	return &alerter.Alert{
		RuleID:      "r_" + tactic,
		Severity:    sev,
		Scope:       alerter.ScopeHost,
		MITRETactic: tactic,
		ServerName:  server,
		Timestamp:   at,
		Reason:      tactic + " on host",
	}
}

func TestHostScopeCorrelatesByServer(t *testing.T) {
	c := New(testConfig())
	t0 := time.Unix(1000, 0)
	c.Observe(hostFinding("web-01", "Execution", alerter.SeverityHigh, t0))
	c.Observe(hostFinding("web-01", "Discovery", alerter.SeverityMedium, t0.Add(time.Second)))
	inc := c.Observe(hostFinding("web-01", "Persistence", alerter.SeverityHigh, t0.Add(2*time.Second)))
	if inc == nil {
		t.Fatal("3 host stages on one server should raise an incident")
	}
	if inc.Scope != alerter.ScopeHost {
		t.Fatalf("host incident must carry scope=host, got %q", inc.Scope)
	}
	// A different host must not share the chain.
	c2 := New(testConfig())
	c2.Observe(hostFinding("web-01", "Execution", alerter.SeverityHigh, t0))
	if inc := c2.Observe(hostFinding("web-02", "Discovery", alerter.SeverityHigh, t0)); inc != nil {
		t.Fatalf("findings from different hosts must not correlate, got %v", inc.Reason)
	}
}

func TestHostThresholdOverride(t *testing.T) {
	// Host bucket demands 4 stages; container default is 3.
	c := New(Config{Window: time.Minute, MinStages: 3, MinScore: 9999, HostMinStages: 4, Cooldown: 0})
	t0 := time.Unix(1000, 0)
	c.Observe(hostFinding("h", "Execution", alerter.SeverityHigh, t0))
	c.Observe(hostFinding("h", "Discovery", alerter.SeverityHigh, t0.Add(time.Second)))
	if inc := c.Observe(hostFinding("h", "Persistence", alerter.SeverityHigh, t0.Add(2*time.Second))); inc != nil {
		t.Fatalf("3 host stages must not fire when HostMinStages=4, got %v", inc.Reason)
	}
	if inc := c.Observe(hostFinding("h", "Credential Access", alerter.SeverityHigh, t0.Add(3*time.Second))); inc == nil {
		t.Fatal("4th host stage should cross HostMinStages=4")
	}
}

func TestStaleBucketsAreGarbageCollected(t *testing.T) {
	// No incidents (thresholds unreachable) — we only care about bucket lifecycle.
	c := New(Config{Window: 30 * time.Second, MinStages: 99, MinScore: 9999, Cooldown: 0})
	t0 := time.Unix(1000, 0)

	// Six distinct containers leave a finding at t0.
	for _, id := range []string{"c0", "c1", "c2", "c3", "c4", "c5"} {
		c.Observe(finding(id, "Execution", alerter.SeverityHigh, t0))
	}
	if got := len(c.by); got != 6 {
		t.Fatalf("expected 6 live buckets, got %d", got)
	}

	// A new finding well past window+cooldown triggers a sweep that drops every
	// bucket whose last activity has aged out, leaving only the fresh one.
	c.Observe(finding("c6", "Execution", alerter.SeverityHigh, t0.Add(61*time.Second)))
	if got := len(c.by); got != 1 {
		t.Fatalf("stale buckets should have been collected, got %d live", got)
	}
}

func TestSeparateContainersDoNotMix(t *testing.T) {
	c := New(testConfig())
	t0 := time.Unix(1000, 0)
	c.Observe(finding("c1", "Execution", alerter.SeverityHigh, t0))
	c.Observe(finding("c2", "Discovery", alerter.SeverityHigh, t0))
	if inc := c.Observe(finding("c1", "Credential Access", alerter.SeverityHigh, t0)); inc != nil {
		t.Fatalf("c1 has only 2 stages; c2's stage must not count, got %v", inc.Reason)
	}
}
