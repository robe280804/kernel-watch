// Package suppress holds the operator-defined false-positive model shared by the
// detector (which applies suppressions on the hot path) and, later, the storage
// and API layers (which persist and expose them). Keeping the type in a
// dependency-free leaf package avoids an import cycle between those packages.
//
// A suppression is the operational answer to "this alert is a false positive,
// stop showing it to me": rather than only editing config and redeploying, an
// operator can express a structured rule; the detector swaps in the active set
// atomically and silently drops matching findings from then on.
package suppress

import (
	"strings"
	"time"
)

// Rule is a false-positive filter. An alert is suppressed only when EVERY
// non-empty field of the rule matches that alert, so criteria are ANDed and a
// more specific rule silences less. A rule with no PRIMARY criteria set (see
// Empty) matches nothing — deliberate, so a malformed/empty rule can never
// blanket-silence the whole monitor.
//
// Scope and Hostname are NARROWING-ONLY: they further restrict a rule but cannot
// be its sole criteria (Empty ignores them). This matters because the fleet
// shares one database — a Hostname-scoped suppression silences one noisy host
// without affecting the rest — while still forbidding a blanket "silence all of
// scope=host" rule.
type Rule struct {
	ID            string    `json:"id,omitempty"`
	RuleID        string    `json:"rule_id,omitempty"`        // detection rule id (e.g. "network_tool"); empty = any rule
	Scope         string    `json:"scope,omitempty"`          // "host" | "container"; empty = any scope
	Hostname      string    `json:"hostname,omitempty"`       // server name; empty = any host
	ContainerName string    `json:"container_name,omitempty"` // empty = any container
	ProcessName   string    `json:"process_name,omitempty"`   // empty = any process
	Substr        string    `json:"substr,omitempty"`         // case-insensitive substring of name/image/cmdline/ancestry
	Reason        string    `json:"reason,omitempty"`         // operator note: why this is a false positive
	CreatedBy     string    `json:"created_by,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
}

// Target is the set of alert attributes a suppression rule is matched against.
type Target struct {
	RuleID        string
	Scope         string
	Hostname      string
	ContainerName string
	ProcessName   string
	Haystack      string // combined free-text context (name/image/cmdline/ancestry)
}

// Empty reports whether the rule carries no PRIMARY matching criteria. Such a
// rule is rejected on input and is never applied by the detector. Scope and
// Hostname are deliberately excluded here so they cannot stand alone.
func (r Rule) Empty() bool {
	return strings.TrimSpace(r.RuleID) == "" &&
		strings.TrimSpace(r.ContainerName) == "" &&
		strings.TrimSpace(r.ProcessName) == "" &&
		strings.TrimSpace(r.Substr) == ""
}

// Match reports whether this rule suppresses the given alert target.
func (r Rule) Match(t Target) bool {
	if r.Empty() {
		return false
	}
	if s := strings.TrimSpace(r.RuleID); s != "" && !strings.EqualFold(s, t.RuleID) {
		return false
	}
	if s := strings.TrimSpace(r.Scope); s != "" && !strings.EqualFold(s, t.Scope) {
		return false
	}
	if s := strings.TrimSpace(r.Hostname); s != "" && !strings.EqualFold(s, t.Hostname) {
		return false
	}
	if s := strings.TrimSpace(r.ContainerName); s != "" && !strings.EqualFold(s, t.ContainerName) {
		return false
	}
	if s := strings.TrimSpace(r.ProcessName); s != "" && !strings.EqualFold(s, t.ProcessName) {
		return false
	}
	if s := strings.TrimSpace(r.Substr); s != "" && !strings.Contains(strings.ToLower(t.Haystack), strings.ToLower(s)) {
		return false
	}
	return true
}

// Set is a collection of active suppression rules.
type Set []Rule

// Suppresses reports whether any rule in the set matches the given alert target.
func (s Set) Suppresses(t Target) bool {
	for _, r := range s {
		if r.Match(t) {
			return true
		}
	}
	return false
}
