package detector

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/collector"
	"kernelwatch/internal/config"
)

// Detector evaluates the ruleset against events, applying lineage context,
// operator exceptions, and short-window deduplication. Unlike the old
// first-match design it runs ALL rules, so one event can raise several
// independent findings (e.g. drift + reverse-shell).
type Detector struct {
	rules      []Rule
	class      *classifier
	exceptions []string

	mu       sync.Mutex
	seen     map[string]time.Time // ruleID|container|pid → last emit
	dedupTTL time.Duration
}

// New builds a Detector from config (parent-class overrides + exceptions).
func New(cfg *config.Config) *Detector {
	exc := make([]string, 0, len(cfg.DetectionExceptions))
	for _, e := range cfg.DetectionExceptions {
		if s := strings.ToLower(strings.TrimSpace(e)); s != "" {
			exc = append(exc, s)
		}
	}
	return &Detector{
		rules:      defaultRules(),
		class:      newClassifier(cfg.TrustedParents, cfg.NetworkParents),
		exceptions: exc,
		seen:       make(map[string]time.Time),
		dedupTTL:   30 * time.Second,
	}
}

// Check runs every rule against an event and returns all (deduplicated,
// non-excepted) alerts. Host events (no container) are ignored.
func (d *Detector) Check(e collector.Event) []*alerter.Alert {
	if e.Container == nil {
		return nil
	}
	if d.excepted(e) {
		return nil
	}

	var alerts []*alerter.Alert
	for i := range d.rules {
		r := &d.rules[i]
		m := r.Match(e, d.class)
		if m == nil {
			continue
		}
		if d.duplicate(r.ID, e) {
			continue
		}
		alerts = append(alerts, buildAlert(r, m, e))
	}
	return alerts
}

// excepted suppresses an event if any configured exception substring appears in
// the container name, image, command line, or ancestry — the tuning escape hatch.
func (d *Detector) excepted(e collector.Event) bool {
	if len(d.exceptions) == 0 {
		return false
	}
	hay := strings.ToLower(strings.Join([]string{
		e.Container.Name, e.Container.ImageName, e.CmdLine, strings.Join(e.Ancestry, " "),
	}, " "))
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
	key := fmt.Sprintf("%s|%s|%d", ruleID, e.Container.ID, e.PID)
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

// buildAlert turns a rule + hit + event into a fully-stamped Alert.
func buildAlert(r *Rule, m *hit, e collector.Event) *alerter.Alert {
	sev := r.Severity
	if m.Severity != "" {
		sev = m.Severity
	}
	var parent string
	if len(e.Ancestry) > 0 {
		parent = e.Ancestry[0]
	}
	return &alerter.Alert{
		RuleID:        r.ID,
		Severity:      sev,
		Reason:        m.Reason,
		MITRETTP:      r.Technique,
		MITRETactic:   r.Tactic,
		Tags:          r.Tags,
		ContainerID:   e.Container.ID,
		ContainerName: e.Container.Name,
		ImageName:     e.Container.ImageName,
		PID:           e.PID,
		ProcessName:   processName(e),
		ParentName:    parent,
		Ancestry:      e.Ancestry,
		CmdLine:       e.CmdLine,
		Syscall:       e.TypeName(),
		Timestamp:     e.Timestamp,
		Details:       m.Details,
	}
}
