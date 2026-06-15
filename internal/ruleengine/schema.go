package ruleengine

import "gopkg.in/yaml.v3"

// File is a parsed YAML ruleset document: reusable lists, reusable condition
// macros, and the rules themselves. Multiple files are merged (default +
// operator overrides) before compilation.
type File struct {
	Lists       map[string][]string `yaml:"lists"`
	AppendLists map[string][]string `yaml:"append_lists"` // extend an existing list instead of replacing it
	Macros      map[string]string   `yaml:"macros"`
	Rules       []RuleSpec          `yaml:"rules"`
}

// RuleSpec is a single declarative rule.
type RuleSpec struct {
	ID        string            `yaml:"id"`
	Desc      string            `yaml:"desc"`
	Scope     string            `yaml:"scope"` // container | host | all (default all)
	Tactic    string            `yaml:"tactic"`
	Technique string            `yaml:"technique"`
	Tags      []string          `yaml:"tags"`
	Enabled   *bool             `yaml:"enabled"` // nil = true
	Condition string            `yaml:"condition"`
	Severity  string            `yaml:"severity"`
	Reason    string            `yaml:"reason"`
	Details   map[string]string `yaml:"details"`
	Lineage   []ArmSpec         `yaml:"lineage"`
	Exceptions []ExceptionSpec  `yaml:"exceptions"`

	// Merge semantics for operator override files (ignored in the embedded default):
	Append   bool `yaml:"append"`   // extend tags/exceptions of an existing rule
	Override bool `yaml:"override"` // replace an existing rule wholesale
}

// ArmSpec is one branch of the lineage matrix. The first arm whose `when`
// matches the event's lineage AND whose optional `and` guard is true decides the
// outcome: either suppress (no alert) or a severity+reason(+details). A rule with
// arms but no matching arm is suppressed. A rule with no arms uses the top-level
// severity/reason/details whenever its condition is true.
type ArmSpec struct {
	When    StringOrSlice     `yaml:"when"`   // network|interactive|trusted|unknown|any (one or many)
	And     string            `yaml:"and"`    // optional extra guard condition (DSL)
	Action  string            `yaml:"action"` // "" or "suppress"
	Severity string           `yaml:"severity"`
	Reason  string            `yaml:"reason"`
	Details map[string]string `yaml:"details"`
}

// ExceptionSpec is a Falco-style per-rule exception: when, for some value tuple,
// every (field comp value) holds, the alert is suppressed. Used by operators to
// carve out known-good activity without forking a managed rule.
type ExceptionSpec struct {
	Name   string     `yaml:"name"`
	Fields []string   `yaml:"fields"`
	Comps  []string   `yaml:"comps"`  // per-field: = | in | contains | startswith (default =)
	Values [][]string `yaml:"values"` // rows of values, one per field
}

// StringOrSlice accepts either a scalar (`when: network`) or a sequence
// (`when: [unknown, interactive]`) in YAML.
type StringOrSlice []string

// UnmarshalYAML implements yaml.v3's Unmarshaler for the scalar-or-sequence form.
func (s *StringOrSlice) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		var one string
		if err := value.Decode(&one); err != nil {
			return err
		}
		*s = []string{one}
		return nil
	}
	var many []string
	if err := value.Decode(&many); err != nil {
		return err
	}
	*s = many
	return nil
}
