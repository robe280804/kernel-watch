package ruleengine

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Load builds an Engine from the embedded default ruleset, then merges an
// optional operator rules file and/or a directory of *.yaml rules on top (files
// applied in lexical order). Operator rules can override, append to, or extend
// the managed defaults. Returns an error if any file fails to parse, a merge is
// illegal (e.g. a duplicate id without override), or compilation fails.
func Load(rulesFile, rulesDir string) (*Engine, error) {
	base, err := parseFile(defaultYAML, "default.yaml")
	if err != nil {
		return nil, fmt.Errorf("embedded default ruleset: %w", err)
	}

	var overlays []string
	if rulesFile != "" {
		overlays = append(overlays, rulesFile)
	}
	if rulesDir != "" {
		entries, err := os.ReadDir(rulesDir)
		if err != nil {
			return nil, fmt.Errorf("rules dir: %w", err)
		}
		var names []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if ext := filepath.Ext(e.Name()); ext == ".yaml" || ext == ".yml" {
				names = append(names, filepath.Join(rulesDir, e.Name()))
			}
		}
		sort.Strings(names)
		overlays = append(overlays, names...)
	}

	for _, path := range overlays {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		over, err := parseFile(data, path)
		if err != nil {
			return nil, err
		}
		if err := base.mergeOver(over); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}

	if err := base.checkUniqueIDs(); err != nil {
		return nil, err
	}
	rules, err := compileRuleset(base)
	if err != nil {
		return nil, err
	}
	return &Engine{rules: rules}, nil
}

// LoadDefault builds an Engine from only the embedded default ruleset.
func LoadDefault() (*Engine, error) { return Load("", "") }

// Validate compiles the (default + operator) ruleset and reports any error. Used
// by the `--validate` CLI flag and CI linting; needs neither root nor eBPF.
func Validate(rulesFile, rulesDir string) error {
	_, err := Load(rulesFile, rulesDir)
	return err
}

// DefaultFile parses just the embedded default ruleset (for tests/introspection).
func DefaultFile() (*File, error) { return parseFile(defaultYAML, "default.yaml") }

func parseFile(data []byte, name string) (*File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // reject unknown keys — typos in operator files fail fast
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	return &f, nil
}

func (f *File) mergeOver(o *File) error {
	if f.Lists == nil {
		f.Lists = map[string][]string{}
	}
	for k, v := range o.Lists {
		f.Lists[k] = v
	}
	for k, v := range o.AppendLists {
		f.Lists[k] = append(append([]string{}, f.Lists[k]...), v...)
	}
	if f.Macros == nil {
		f.Macros = map[string]string{}
	}
	for k, v := range o.Macros {
		f.Macros[k] = v
	}

	idx := map[string]int{}
	for i := range f.Rules {
		idx[f.Rules[i].ID] = i
	}
	for ri := range o.Rules {
		r := o.Rules[ri]
		i, exists := idx[r.ID]
		switch {
		case r.Override:
			if exists {
				f.Rules[i] = r
			} else {
				idx[r.ID] = len(f.Rules)
				f.Rules = append(f.Rules, r)
			}
		case r.Append:
			if !exists {
				return fmt.Errorf("append to unknown rule %q", r.ID)
			}
			f.Rules[i].Tags = append(f.Rules[i].Tags, r.Tags...)
			f.Rules[i].Exceptions = append(f.Rules[i].Exceptions, r.Exceptions...)
			if r.Enabled != nil {
				f.Rules[i].Enabled = r.Enabled
			}
		default:
			if exists {
				return fmt.Errorf("duplicate rule id %q (use override: true or append: true)", r.ID)
			}
			idx[r.ID] = len(f.Rules)
			f.Rules = append(f.Rules, r)
		}
	}
	return nil
}

func (f *File) checkUniqueIDs() error {
	seen := map[string]bool{}
	for i := range f.Rules {
		id := f.Rules[i].ID
		if id == "" {
			return fmt.Errorf("rule %d has no id", i)
		}
		if seen[id] {
			return fmt.Errorf("duplicate rule id %q", id)
		}
		seen[id] = true
	}
	return nil
}
