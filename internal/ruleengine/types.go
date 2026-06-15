// Package ruleengine turns detection rules from compiled Go into DATA: a
// YAML ruleset (lists + macros + rules) with a small Falco-style condition DSL,
// compiled once into closures and evaluated per event. This is what lets an
// operator add, tune, disable, or override a rule WITHOUT recompiling the binary
// — the defining property of a Falco-grade runtime security tool.
//
// The package is deliberately dependency-light (only collector, alerter, and
// gopkg.in/yaml.v3) and dependency-free of the detector internals: the detector
// adapts its existing lineage classifier to the LineageProvider interface, so the
// hard-won classification logic in internal/detector/lists.go is REUSED, not
// reimplemented.
package ruleengine

import "kernelwatch/internal/alerter"

// Scope is the bitmask of scopes a rule applies to (mirrors the detector's
// scope dimension: container vs whole-host).
type Scope uint8

const (
	ScopeContainer Scope = 1 << iota
	ScopeHost
)

// ScopeAll matches both scopes.
const ScopeAll = ScopeContainer | ScopeHost

// Lineage is the process-ancestry classification produced by the LineageProvider.
// Precedence (highest first) is network > interactive > trusted > unknown; it is
// computed by the detector's classifier and only consumed here.
type Lineage int

const (
	LineageUnknown Lineage = iota
	LineageTrusted
	LineageInteractive
	LineageNetwork
)

// lineageNames maps the YAML `when:` tokens onto Lineage values.
var lineageNames = map[string]Lineage{
	"unknown":     LineageUnknown,
	"trusted":     LineageTrusted,
	"interactive": LineageInteractive,
	"network":     LineageNetwork,
}

// String renders a Lineage as the token used in conditions/details.
func (l Lineage) String() string {
	switch l {
	case LineageNetwork:
		return "network"
	case LineageInteractive:
		return "interactive"
	case LineageTrusted:
		return "trusted"
	default:
		return "unknown"
	}
}

// LineageProvider is the tiny surface the engine needs from the detector's
// classifier. Implemented by an adapter in the detector package (avoids an import
// cycle and reuses the classifier verbatim).
type LineageProvider interface {
	// Classify returns the lineage of an ancestry chain; host is true for
	// host-scope events (some parents are trusted only on the host).
	Classify(ancestry []string, host bool) Lineage
	// TrustedWriter reports whether a process chain (own comm + ancestry) is a
	// legitimate writer of host config/persistence locations.
	TrustedWriter(chain []string) bool
	// NetworkParent returns the first network-facing ancestor (for alert context).
	NetworkParent(ancestry []string) string
	// IsDockerClient reports whether a comm is an expected Docker-socket client.
	IsDockerClient(comm string) bool
}

// Result is a single rule match, already resolved (severity/reason/details).
// It carries exactly the fields the detector needs to build an *alerter.Alert,
// and RuleID equals the legacy rule ids so dedup/suppression keys are unchanged.
type Result struct {
	RuleID    string
	Reason    string
	Severity  alerter.Severity
	Tactic    string
	Technique string
	Tags      []string
	Details   map[string]any
}

// parseSeverity maps a YAML severity token onto an alerter.Severity.
func parseSeverity(s string) (alerter.Severity, bool) {
	switch s {
	case "low":
		return alerter.SeverityLow, true
	case "medium":
		return alerter.SeverityMedium, true
	case "high":
		return alerter.SeverityHigh, true
	case "critical":
		return alerter.SeverityCritical, true
	default:
		return "", false
	}
}
