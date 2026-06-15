// Package correlator turns a stream of independent findings into attack-chain
// incidents. A single suspicious syscall is often ambiguous; a sequence of them
// from the same container's process tree — a shell, then recon, then credential
// access, then a persistence write — is an intrusion in progress.
//
// The engine keeps a short, per-container sliding window of findings, scores
// each by severity (risk points), and tracks which distinct MITRE ATT&CK
// kill-chain stages have been reached. When a container crosses a threshold —
// enough distinct stages OR enough accumulated risk — it emits ONE consolidated,
// escalated incident summarizing the chain, instead of letting the operator
// reassemble it from scattered alerts. This raises true-positive confidence and
// sharply cuts alert fatigue.
//
// It is intentionally deterministic and explainable (no learning phase): every
// incident lists exactly which findings and stages produced it.
package correlator

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"kernelwatch/internal/alerter"
)

// IncidentRuleID is the synthetic rule id carried by correlated incidents.
const IncidentRuleID = "attack_chain"

// severityRisk assigns risk points per finding severity. Tuned so that ~2–3
// high-severity findings, or one critical plus supporting activity, crosses the
// default KW_CORRELATION_MIN_SCORE (120).
var severityRisk = map[alerter.Severity]int{
	alerter.SeverityLow:      10,
	alerter.SeverityMedium:   25,
	alerter.SeverityHigh:     50,
	alerter.SeverityCritical: 100,
}

// Config tunes the correlation engine.
type Config struct {
	Window    time.Duration // sliding window over which findings are correlated
	MinStages int           // distinct kill-chain stages required to raise an incident
	MinScore  int           // OR: accumulated risk score required to raise an incident
	Cooldown  time.Duration // minimum spacing between incidents for the same container
	// Host-scope overrides. Fleets often want a wider chain on the noisier host
	// bucket before raising an incident. 0 = inherit MinStages/MinScore.
	HostMinStages int
	HostMinScore  int
}

// contribution is one finding's mark on a container's chain.
type contribution struct {
	at     time.Time
	ruleID string
	tactic string // MITRE tactic = kill-chain stage
	score  int
}

// containerState is the windowed chain for a single container.
type containerState struct {
	contribs     []contribution
	last         alerter.Alert // most recent finding, for incident context
	lastSig      string        // stage signature of the last emitted incident
	lastEmit     time.Time
	lastSeen     time.Time // last time a finding landed in this bucket (for GC)
}

// Correlator is a concurrency-safe attack-chain engine. Observe is expected to
// be called from the single event-loop goroutine, but the mutex keeps it safe
// if that ever changes.
type Correlator struct {
	cfg    Config
	mu     sync.Mutex
	by     map[string]*containerState // container id → chain state
	lastGC time.Time                  // last time stale buckets were swept
}

// New builds a Correlator, applying sane defaults for any zero-valued field.
func New(cfg Config) *Correlator {
	if cfg.Window <= 0 {
		cfg.Window = 5 * time.Minute
	}
	if cfg.MinStages <= 0 {
		cfg.MinStages = 3
	}
	if cfg.MinScore <= 0 {
		cfg.MinScore = 120
	}
	if cfg.Cooldown < 0 {
		cfg.Cooldown = 0
	}
	if cfg.HostMinStages <= 0 {
		cfg.HostMinStages = cfg.MinStages
	}
	if cfg.HostMinScore <= 0 {
		cfg.HostMinScore = cfg.MinScore
	}
	return &Correlator{cfg: cfg, by: map[string]*containerState{}}
}

// chainKey is the correlation bucket for an alert: the container id for
// container-scope findings, or a per-host key for host-scope findings (the fleet
// shares one engine, so each host needs its own chain). Returns "" when the
// finding cannot be correlated.
func chainKey(a *alerter.Alert) string {
	if a.ContainerID != "" {
		return a.ContainerID
	}
	if a.Scope == alerter.ScopeHost {
		return "host:" + a.ServerName
	}
	return ""
}

// Observe records a finding and returns a consolidated incident alert if the
// finding pushes its container's chain across the threshold, otherwise nil.
//
// Incidents themselves (IsIncident) are never re-correlated — only primary
// findings feed the chain.
func (c *Correlator) Observe(a *alerter.Alert) *alerter.Alert {
	if a == nil || a.IsIncident() {
		return nil
	}
	key := chainKey(a)
	if key == "" {
		return nil
	}
	now := a.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Amortized GC: container ids churn (every new container is a new bucket), so
	// without this the map would grow unbounded over the daemon's lifetime. Sweep
	// at most once per window and only drop buckets that can no longer influence
	// correlation (all contributions window-expired and past any cooldown).
	c.gcLocked(now)

	st := c.by[key]
	if st == nil {
		st = &containerState{}
		c.by[key] = st
	}
	st.last = *a
	st.lastSeen = now
	st.contribs = append(st.contribs, contribution{
		at:     now,
		ruleID: a.RuleID,
		tactic: a.MITRETactic,
		score:  severityRisk[a.Severity],
	})

	// Evict anything older than the window.
	cutoff := now.Add(-c.cfg.Window)
	kept := st.contribs[:0]
	for _, ct := range st.contribs {
		if ct.at.After(cutoff) {
			kept = append(kept, ct)
		}
	}
	st.contribs = kept

	minStages, minScore := c.cfg.MinStages, c.cfg.MinScore
	if a.Scope == alerter.ScopeHost {
		minStages, minScore = c.cfg.HostMinStages, c.cfg.HostMinScore
	}

	stages, score, ruleIDs := summarize(st.contribs)
	qualifies := len(stages) >= minStages || score >= minScore
	if !qualifies {
		return nil
	}

	// Emit once per distinct stage-set: a new stage joining the chain is an
	// escalation worth re-alerting, but repeated activity within the same set is
	// not. The cooldown is a hard floor against flapping near a threshold.
	sig := strings.Join(stages, ">")
	if sig == st.lastSig {
		return nil
	}
	if !st.lastEmit.IsZero() && now.Sub(st.lastEmit) < c.cfg.Cooldown {
		return nil
	}
	st.lastSig = sig
	st.lastEmit = now

	return c.buildIncident(st, stages, score, ruleIDs, now, minStages, minScore)
}

// gcLocked deletes chain buckets that have seen no activity for longer than the
// window plus the cooldown — by then their contributions are all window-expired
// and no cooldown is pending, so the bucket cannot affect any future incident.
// Runs at most once per window (cheap amortization); caller must hold c.mu.
func (c *Correlator) gcLocked(now time.Time) {
	if !c.lastGC.IsZero() && now.Sub(c.lastGC) < c.cfg.Window {
		return
	}
	c.lastGC = now
	ttl := c.cfg.Window + c.cfg.Cooldown
	for key, st := range c.by {
		if now.Sub(st.lastSeen) > ttl {
			delete(c.by, key)
		}
	}
}

// summarize returns the distinct kill-chain stages (ordered by kill-chain rank),
// the total risk score, and the distinct contributing rule ids.
func summarize(contribs []contribution) (stages []string, score int, ruleIDs []string) {
	stageSet := map[string]bool{}
	ruleSet := map[string]bool{}
	for _, ct := range contribs {
		score += ct.score
		if t := strings.TrimSpace(ct.tactic); t != "" {
			stageSet[t] = true
		}
		if ct.ruleID != "" {
			ruleSet[ct.ruleID] = true
		}
	}
	for s := range stageSet {
		stages = append(stages, s)
	}
	sort.Slice(stages, func(i, j int) bool {
		ri, rj := alerter.KillChainRank(stages[i]), alerter.KillChainRank(stages[j])
		if ri != rj {
			return ri < rj
		}
		return stages[i] < stages[j]
	})
	for r := range ruleSet {
		ruleIDs = append(ruleIDs, r)
	}
	sort.Strings(ruleIDs)
	return stages, score, ruleIDs
}

// buildIncident constructs the consolidated alert. Severity escalates with the
// breadth of the chain and the accumulated risk.
func (c *Correlator) buildIncident(st *containerState, stages []string, score int, ruleIDs []string, now time.Time, minStages, minScore int) *alerter.Alert {
	sev := alerter.SeverityHigh
	if len(stages) >= minStages+1 || score >= minScore*2 {
		sev = alerter.SeverityCritical
	}

	last := st.last
	reason := fmt.Sprintf("attack chain detected across %d kill-chain stages (%s) — risk %d from %d findings",
		len(stages), strings.Join(stages, " → "), score, len(st.contribs))

	// The latest stage reached is the incident's headline tactic.
	tactic := ""
	if len(stages) > 0 {
		tactic = stages[len(stages)-1]
	}

	return &alerter.Alert{
		RuleID:         IncidentRuleID,
		Severity:       sev,
		Scope:          last.Scope,
		Reason:         reason,
		MITRETactic:    tactic,
		KillChainPhase: tactic,
		Tags:           []string{alerter.TagAttackChain, "incident", "correlation"},
		RiskScore:      score,
		ContainerID:    last.ContainerID,
		ContainerName:  last.ContainerName,
		ImageName:      last.ImageName,
		ServerName:     last.ServerName,
		PID:            last.PID,
		ProcessName:    last.ProcessName,
		ParentName:     last.ParentName,
		Ancestry:       last.Ancestry,
		CmdLine:        last.CmdLine,
		Timestamp:      now,
		Details: map[string]any{
			"risk_score":     score,
			"stages":         stages,
			"finding_count":  len(st.contribs),
			"rules":          ruleIDs,
			"window_seconds": int(c.cfg.Window.Seconds()),
			"last_finding":   last.Reason,
		},
	}
}
