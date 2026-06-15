package detector

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/collector"
	"kernelwatch/internal/config"
	"kernelwatch/internal/ruleengine"
	"kernelwatch/internal/suppress"
)

// Detector evaluates the ruleset against events, applying lineage context,
// operator exceptions, and short-window deduplication. Unlike the old
// first-match design it runs ALL rules, so one event can raise several
// independent findings (e.g. drift + reverse-shell).
type Detector struct {
	class      *classifier
	lp         ruleengine.LineageProvider // classifier adapted to the engine's interface
	exceptions []string
	serverName string // this host's identity, stamped on host-scope suppression checks

	// engine is the compiled YAML ruleset, swapped atomically on hot reload
	// (mirrors the suppression set pattern below).
	engMu sync.RWMutex
	eng   *ruleengine.Engine

	mu       sync.Mutex
	seen     map[string]time.Time // ruleID|container|pid → last emit
	dedupTTL time.Duration

	// suppressions are operator-defined false-positive rules, swapped in
	// atomically (e.g. by a periodic reload). Consulted after a rule matches but
	// before the alert is emitted.
	suppMu sync.RWMutex
	supp   suppress.Set
}

// SetSuppressions atomically replaces the active suppression set. Safe to call
// concurrently with Check (e.g. from a background reloader).
func (d *Detector) SetSuppressions(s suppress.Set) {
	d.suppMu.Lock()
	d.supp = s
	d.suppMu.Unlock()
}

// SetRuleset atomically replaces the active compiled ruleset. Safe to call
// concurrently with Check (e.g. from a background rules reloader). A nil ruleset
// is ignored so a failed reload never disarms the detector.
func (d *Detector) SetRuleset(e *ruleengine.Engine) {
	if e == nil {
		return
	}
	d.engMu.Lock()
	d.eng = e
	d.engMu.Unlock()
}

// engine returns the active compiled ruleset under a read lock.
func (d *Detector) engine() *ruleengine.Engine {
	d.engMu.RLock()
	defer d.engMu.RUnlock()
	return d.eng
}

// suppressions returns the current set under a read lock.
func (d *Detector) suppressions() suppress.Set {
	d.suppMu.RLock()
	defer d.suppMu.RUnlock()
	return d.supp
}

// New builds a Detector from config (parent-class overrides + exceptions).
func New(cfg *config.Config) *Detector {
	exc := make([]string, 0, len(cfg.DetectionExceptions))
	for _, e := range cfg.DetectionExceptions {
		if s := strings.ToLower(strings.TrimSpace(e)); s != "" {
			exc = append(exc, s)
		}
	}
	class := newClassifier(cfg)

	// Load the YAML ruleset: embedded defaults + optional operator overrides.
	// A failed user file must never disarm the monitor, so on error we fall back
	// to the embedded defaults.
	eng, err := ruleengine.Load(cfg.RulesFile, cfg.RulesDir)
	if err != nil {
		slog.Error("rule engine load failed, falling back to embedded defaults", "err", err)
		eng, err = ruleengine.LoadDefault()
		if err != nil {
			slog.Error("embedded default ruleset failed to compile", "err", err)
		}
	}

	return &Detector{
		class:      class,
		lp:         lineageAdapter{c: class},
		exceptions: exc,
		serverName: cfg.ServerName,
		eng:        eng,
		seen:       make(map[string]time.Time),
		dedupTTL:   30 * time.Second,
	}
}

// lineageAdapter adapts the detector's classifier to ruleengine.LineageProvider,
// so the engine reuses the classification logic in lists.go verbatim.
type lineageAdapter struct{ c *classifier }

func (a lineageAdapter) Classify(ancestry []string, host bool) ruleengine.Lineage {
	s := scopeContainer
	if host {
		s = scopeHost
	}
	switch a.c.classify(ancestry, s) {
	case lineageNetwork:
		return ruleengine.LineageNetwork
	case lineageInteractive:
		return ruleengine.LineageInteractive
	case lineageTrusted:
		return ruleengine.LineageTrusted
	default:
		return ruleengine.LineageUnknown
	}
}

func (a lineageAdapter) TrustedWriter(chain []string) bool   { return a.c.trustedWriter(chain) }
func (a lineageAdapter) NetworkParent(ancestry []string) string { return a.c.networkParent(ancestry) }
func (a lineageAdapter) IsDockerClient(comm string) bool      { return a.c.isDockerClient(comm) }

// Check runs every in-scope rule against an event and returns all
// (deduplicated, non-excepted) alerts. Both container and host events are
// evaluated; each rule declares which scopes it applies to and branches on the
// event's scope internally.
func (d *Detector) Check(e collector.Event) []*alerter.Alert {
	if d.excepted(e) {
		return nil
	}

	eng := d.engine()
	if eng == nil {
		return nil
	}

	scope := ruleengine.ScopeContainer
	scopeStr := alerter.ScopeContainer
	if e.IsHost() {
		scope = ruleengine.ScopeHost
		scopeStr = alerter.ScopeHost
	}

	supp := d.suppressions()
	hay := eventHaystack(e)
	proc := processName(e)
	contName, host := "", ""
	if e.Container != nil {
		contName = e.Container.Name
	} else {
		host = d.serverName
	}

	var alerts []*alerter.Alert
	for _, res := range eng.Match(e, d.lp, scope) {
		// Operator-defined false-positive suppression. Checked before dedup so a
		// suppressed finding never occupies a dedup slot.
		if len(supp) > 0 && supp.Suppresses(suppress.Target{
			RuleID: res.RuleID, Scope: scopeStr, Hostname: host,
			ContainerName: contName, ProcessName: proc, Haystack: hay,
		}) {
			continue
		}
		if d.duplicate(res.RuleID, e) {
			continue
		}
		alerts = append(alerts, buildAlert(res, e))
	}
	return alerts
}

// eventHaystack is the combined free-text context of an event, used by both the
// config exceptions and the operator suppression rules. Host events carry no
// container, so those fields are simply empty.
func eventHaystack(e collector.Event) string {
	name, image := "", ""
	if e.Container != nil {
		name, image = e.Container.Name, e.Container.ImageName
	}
	return strings.ToLower(strings.Join([]string{
		name, image, e.CmdLine, strings.Join(e.Ancestry, " "),
	}, " "))
}

// excepted suppresses an event if any configured exception substring appears in
// the container name, image, command line, or ancestry — the tuning escape hatch.
func (d *Detector) excepted(e collector.Event) bool {
	if len(d.exceptions) == 0 {
		return false
	}
	hay := eventHaystack(e)
	for _, ex := range d.exceptions {
		if strings.Contains(hay, ex) {
			return true
		}
	}
	return false
}

// duplicate returns true if the same (rule, container, pid) fired within the
// dedup window. Also lazily evicts expired keys.
func (d *Detector) duplicate(ruleID string, e collector.Event) bool {
	scopeKey := "host"
	if e.Container != nil {
		scopeKey = e.Container.ID
	}
	key := fmt.Sprintf("%s|%s|%d", ruleID, scopeKey, e.PID)
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()
	for k, t := range d.seen {
		if now.Sub(t) > d.dedupTTL {
			delete(d.seen, k)
		}
	}
	if t, ok := d.seen[key]; ok && now.Sub(t) <= d.dedupTTL {
		return true
	}
	d.seen[key] = now
	return false
}

// buildAlert turns an engine Result + event into a fully-stamped Alert.
func buildAlert(res ruleengine.Result, e collector.Event) *alerter.Alert {
	var parent string
	if len(e.Ancestry) > 0 {
		parent = e.Ancestry[0]
	}
	a := &alerter.Alert{
		RuleID:         res.RuleID,
		Severity:       res.Severity,
		Reason:         res.Reason,
		Scope:          alerter.ScopeContainer,
		MITRETTP:       res.Technique,
		MITRETactic:    res.Tactic,
		KillChainPhase: res.Tactic, // the MITRE tactic IS the kill-chain stage
		Tags:           res.Tags,
		PID:            e.PID,
		ProcessName:    processName(e),
		ParentName:     parent,
		Ancestry:       e.Ancestry,
		CmdLine:        e.CmdLine,
		Syscall:        e.TypeName(),
		Timestamp:      e.Timestamp,
		Details:        res.Details,
	}
	if e.Container != nil {
		a.ContainerID = e.Container.ID
		a.ContainerName = e.Container.Name
		a.ImageName = e.Container.ImageName
	} else {
		a.Scope = alerter.ScopeHost
	}
	return a
}
