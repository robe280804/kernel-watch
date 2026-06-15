package ruleengine

import (
	"strings"

	"kernelwatch/internal/alerter"
	"kernelwatch/internal/collector"
)

// Engine is an immutable, compiled ruleset. Build one with Load/LoadDefault and
// swap it atomically (the detector wraps it under a RWMutex for hot reload).
type Engine struct {
	rules []*CompiledRule
}

// Rules exposes the compiled rules (read-only) for introspection/tests.
func (e *Engine) Rules() []*CompiledRule { return e.rules }

// Match evaluates every in-scope rule against the event and returns the resolved
// findings, in rule-declaration order. Suppressed rules (trusted lineage, a
// matching exception, or no matching lineage arm) produce no Result.
func (e *Engine) Match(ev collector.Event, c LineageProvider, scope Scope) []Result {
	cx := newEvalCtx(&ev, c, scope)
	var out []Result
	for _, r := range e.rules {
		if r.Scope&scope == 0 {
			continue
		}
		if !r.gate(cx) {
			continue
		}
		res, ok := r.outcome(cx)
		if !ok {
			continue // suppressed
		}
		if r.suppressedByException(cx) {
			continue
		}
		out = append(out, res)
	}
	return out
}

// outcome resolves a matched rule into a Result, or (_, false) if suppressed.
func (r *CompiledRule) outcome(cx *evalCtx) (Result, bool) {
	if !r.hasArms {
		return r.result(cx, r.severity, r.reason, r.details), true
	}
	lin := cx.lineage()
	for i := range r.arms {
		a := &r.arms[i]
		if !a.whenAny && !a.when[lin] {
			continue
		}
		if a.guard != nil && !a.guard(cx) {
			continue
		}
		if a.suppress {
			return Result{}, false
		}
		return r.result(cx, a.severity, a.reason, a.details), true
	}
	return Result{}, false // no arm matched => suppress
}

func (r *CompiledRule) result(cx *evalCtx, sev alerter.Severity, reason string, details []detailKV) Result {
	return Result{
		RuleID:    r.ID,
		Reason:    reason,
		Severity:  sev,
		Tactic:    r.Tactic,
		Technique: r.Technique,
		Tags:      r.Tags,
		Details:   renderDetails(cx, details),
	}
}

// suppressedByException reports whether any compiled exception matches the event.
func (r *CompiledRule) suppressedByException(cx *evalCtx) bool {
	for i := range r.exceptions {
		if r.exceptions[i].matches(cx) {
			return true
		}
	}
	return false
}

func (e *compiledException) matches(cx *evalCtx) bool {
	if len(e.fields) == 0 || len(e.values) == 0 {
		return false // a template with no values matches nothing
	}
	for _, row := range e.values {
		all := true
		for i, sf := range e.fields {
			comp := "="
			if i < len(e.comps) && e.comps[i] != "" {
				comp = e.comps[i]
			}
			if !compareException(sf(cx), comp, row[i]) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func compareException(got, comp, want string) bool {
	switch comp {
	case "in":
		// want is a comma-separated set
		for _, w := range strings.Split(want, ",") {
			if strings.EqualFold(strings.TrimSpace(w), got) {
				return true
			}
		}
		return false
	case "contains":
		return strings.Contains(got, want)
	case "startswith":
		return strings.HasPrefix(got, want)
	default: // "="
		return strings.EqualFold(got, want)
	}
}

// renderDetails resolves each detail token: a known field name yields its value,
// anything else is taken as a literal string.
func renderDetails(cx *evalCtx, kvs []detailKV) map[string]any {
	if len(kvs) == 0 {
		return nil
	}
	m := make(map[string]any, len(kvs))
	for _, kv := range kvs {
		if v, ok := fieldAny(cx, kv.token); ok {
			m[kv.key] = v
		} else {
			m[kv.key] = kv.token
		}
	}
	return m
}
