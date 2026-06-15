package ruleengine

import (
	"fmt"
	"sort"

	"kernelwatch/internal/alerter"
)

// CompiledRule is a rule ready to evaluate: a gate predicate plus either a
// top-level outcome or an ordered lineage matrix, plus optional exceptions.
type CompiledRule struct {
	ID        string
	Scope     Scope
	Tactic    string
	Technique string
	Tags      []string

	gate pred

	hasArms  bool
	severity alerter.Severity // top-level (no arms)
	reason   string
	details  []detailKV
	arms     []compiledArm

	exceptions []compiledException
}

type detailKV struct {
	key   string
	token string
}

type compiledArm struct {
	whenAny  bool
	when     map[Lineage]bool
	guard    pred // nil = always
	suppress bool
	severity alerter.Severity
	reason   string
	details  []detailKV
}

type compiledException struct {
	name   string
	fields []strAccessor
	comps  []string
	values [][]string
}

// compileRuleset compiles every enabled rule in order, resolving macros and
// validating list references along the way.
func compileRuleset(f *File) ([]*CompiledRule, error) {
	resolved, err := resolveMacros(f.Macros)
	if err != nil {
		return nil, err
	}
	var rules []*CompiledRule
	for i := range f.Rules {
		spec := &f.Rules[i]
		if spec.Enabled != nil && !*spec.Enabled {
			continue
		}
		cr, err := compileRule(spec, f.Lists, resolved)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", spec.ID, err)
		}
		rules = append(rules, cr)
	}
	return rules, nil
}

func compileRule(spec *RuleSpec, lists map[string][]string, resolvedMacros map[string]string) (*CompiledRule, error) {
	if spec.ID == "" {
		return nil, fmt.Errorf("missing id")
	}
	scope, err := parseScope(spec.Scope)
	if err != nil {
		return nil, err
	}
	cond, err := applyMacros(spec.Condition, resolvedMacros)
	if err != nil {
		return nil, err
	}
	if cond == "" {
		return nil, fmt.Errorf("empty condition")
	}
	gate, err := compileCondition(cond, lists)
	if err != nil {
		return nil, fmt.Errorf("condition: %w", err)
	}

	cr := &CompiledRule{
		ID: spec.ID, Scope: scope, Tactic: spec.Tactic, Technique: spec.Technique, Tags: spec.Tags,
		gate: gate,
	}

	if len(spec.Lineage) > 0 {
		cr.hasArms = true
		for ai := range spec.Lineage {
			arm, err := compileArm(&spec.Lineage[ai], lists, resolvedMacros)
			if err != nil {
				return nil, fmt.Errorf("lineage arm %d: %w", ai, err)
			}
			cr.arms = append(cr.arms, arm)
		}
	} else {
		sev, ok := parseSeverity(spec.Severity)
		if !ok {
			return nil, fmt.Errorf("invalid or missing severity %q", spec.Severity)
		}
		cr.severity = sev
		cr.reason = spec.Reason
		cr.details = detailList(spec.Details)
	}

	for ei := range spec.Exceptions {
		ce, err := compileException(&spec.Exceptions[ei])
		if err != nil {
			return nil, fmt.Errorf("exception %q: %w", spec.Exceptions[ei].Name, err)
		}
		cr.exceptions = append(cr.exceptions, ce)
	}
	return cr, nil
}

func compileArm(a *ArmSpec, lists map[string][]string, resolvedMacros map[string]string) (compiledArm, error) {
	arm := compiledArm{when: map[Lineage]bool{}}
	if len(a.When) == 0 {
		arm.whenAny = true
	}
	for _, w := range a.When {
		if w == "any" {
			arm.whenAny = true
			continue
		}
		l, ok := lineageNames[w]
		if !ok {
			return arm, fmt.Errorf("invalid lineage %q", w)
		}
		arm.when[l] = true
	}
	if a.And != "" {
		guardCond, err := applyMacros(a.And, resolvedMacros)
		if err != nil {
			return arm, err
		}
		g, err := compileCondition(guardCond, lists)
		if err != nil {
			return arm, fmt.Errorf("guard: %w", err)
		}
		arm.guard = g
	}
	if a.Action == "suppress" {
		arm.suppress = true
		return arm, nil
	}
	if a.Action != "" {
		return arm, fmt.Errorf("invalid action %q (only 'suppress')", a.Action)
	}
	sev, ok := parseSeverity(a.Severity)
	if !ok {
		return arm, fmt.Errorf("invalid or missing severity %q", a.Severity)
	}
	arm.severity = sev
	arm.reason = a.Reason
	arm.details = detailList(a.Details)
	return arm, nil
}

func compileException(e *ExceptionSpec) (compiledException, error) {
	ce := compiledException{name: e.Name}
	for _, f := range e.Fields {
		sf, ok := strFields[f]
		if !ok {
			return ce, fmt.Errorf("unknown field %q", f)
		}
		ce.fields = append(ce.fields, sf)
	}
	ce.comps = e.Comps
	ce.values = e.Values
	for i, row := range e.Values {
		if len(row) != len(e.Fields) {
			return ce, fmt.Errorf("value row %d has %d values, want %d", i, len(row), len(e.Fields))
		}
	}
	return ce, nil
}

func detailList(m map[string]string) []detailKV {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]detailKV, 0, len(m))
	for _, k := range keys {
		out = append(out, detailKV{key: k, token: m[k]})
	}
	return out
}

func parseScope(s string) (Scope, error) {
	switch s {
	case "", "all":
		return ScopeAll, nil
	case "container":
		return ScopeContainer, nil
	case "host":
		return ScopeHost, nil
	default:
		return 0, fmt.Errorf("invalid scope %q (container|host|all)", s)
	}
}
