package ruleengine

import (
	"fmt"
	"strings"
)

// resolveMacros fully expands every macro so its value contains no further macro
// references, detecting cycles via a DFS on-stack set. The returned map can then
// be applied to rule conditions in a single pass.
func resolveMacros(macros map[string]string) (map[string]string, error) {
	resolved := make(map[string]string, len(macros))
	visiting := make(map[string]bool)
	var resolveErr error

	var rec func(name string) string
	rec = func(name string) string {
		if v, ok := resolved[name]; ok {
			return v
		}
		if visiting[name] {
			if resolveErr == nil {
				resolveErr = fmt.Errorf("macro cycle detected at %q", name)
			}
			return ""
		}
		visiting[name] = true
		out, err := substituteWords(macros[name], func(word string) (string, bool) {
			if _, ok := macros[word]; ok {
				return "(" + rec(word) + ")", true
			}
			return "", false
		})
		if err != nil && resolveErr == nil {
			resolveErr = err
		}
		delete(visiting, name)
		resolved[name] = out
		return out
	}

	for name := range macros {
		rec(name)
		if resolveErr != nil {
			break
		}
	}
	return resolved, resolveErr
}

// applyMacros replaces standalone macro-name words in a condition with their
// fully-resolved expansion (wrapped in parens).
func applyMacros(cond string, resolved map[string]string) (string, error) {
	return substituteWords(cond, func(word string) (string, bool) {
		if exp, ok := resolved[word]; ok {
			return "(" + exp + ")", true
		}
		return "", false
	})
}

// substituteWords rebuilds s, invoking fn for each identifier word; if fn returns
// (repl, true) the word is replaced. Double-quoted strings are copied verbatim so
// substitution never reaches inside a literal.
func substituteWords(s string, fn func(word string) (string, bool)) (string, error) {
	var b strings.Builder
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case c == '"':
			j := i + 1
			for j < n && s[j] != '"' {
				j++
			}
			if j >= n {
				return "", fmt.Errorf("unterminated string in condition")
			}
			b.WriteString(s[i : j+1])
			i = j + 1
		case isIdentStart(c):
			j := i
			for j < n && isIdentChar(s[j]) {
				j++
			}
			word := s[i:j]
			if repl, ok := fn(word); ok {
				b.WriteString(repl)
			} else {
				b.WriteString(word)
			}
			i = j
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), nil
}
