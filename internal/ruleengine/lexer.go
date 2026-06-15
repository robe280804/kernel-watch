package ruleengine

import (
	"fmt"
	"strings"
)

// tokKind enumerates the lexical tokens of the condition DSL.
type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tList   // $name
	tString // "..."
	tInt
	tLParen
	tRParen
	tLBrack
	tRBrack
	tComma
	tEq         // =
	tNeq        // !=
	tAmp        // &
	tAnd        // and
	tOr         // or
	tNot        // not
	tIn         // in
	tContains   // contains
	tStartswith // startswith
)

type token struct {
	kind tokKind
	text string
	pos  int
}

// keywords maps reserved words to their token kinds.
var keywords = map[string]tokKind{
	"and": tAnd, "or": tOr, "not": tNot,
	"in": tIn, "contains": tContains, "startswith": tStartswith,
}

// lex tokenizes a condition string. It is intentionally tiny: identifiers may
// contain dots (field paths), integers may be hex (0x...), strings are
// double-quoted, and list references start with '$'.
func lex(src string) ([]token, error) {
	var toks []token
	i, n := 0, len(src)
	for i < n {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{tLParen, "(", i})
			i++
		case c == ')':
			toks = append(toks, token{tRParen, ")", i})
			i++
		case c == '[':
			toks = append(toks, token{tLBrack, "[", i})
			i++
		case c == ']':
			toks = append(toks, token{tRBrack, "]", i})
			i++
		case c == ',':
			toks = append(toks, token{tComma, ",", i})
			i++
		case c == '&':
			toks = append(toks, token{tAmp, "&", i})
			i++
		case c == '=':
			toks = append(toks, token{tEq, "=", i})
			i++
		case c == '!':
			if i+1 < n && src[i+1] == '=' {
				toks = append(toks, token{tNeq, "!=", i})
				i += 2
			} else {
				return nil, fmt.Errorf("unexpected '!' at %d (did you mean '!='?)", i)
			}
		case c == '"':
			j := i + 1
			for j < n && src[j] != '"' {
				j++
			}
			if j >= n {
				return nil, fmt.Errorf("unterminated string at %d", i)
			}
			toks = append(toks, token{tString, src[i+1 : j], i})
			i = j + 1
		case c == '$':
			j := i + 1
			for j < n && isIdentChar(src[j]) {
				j++
			}
			if j == i+1 {
				return nil, fmt.Errorf("empty list reference at %d", i)
			}
			toks = append(toks, token{tList, src[i+1 : j], i})
			i = j
		case c >= '0' && c <= '9':
			j := i
			if c == '0' && i+1 < n && (src[i+1] == 'x' || src[i+1] == 'X') {
				j = i + 2
				for j < n && isHexDigit(src[j]) {
					j++
				}
			} else {
				for j < n && src[j] >= '0' && src[j] <= '9' {
					j++
				}
			}
			toks = append(toks, token{tInt, src[i:j], i})
			i = j
		case isIdentStart(c):
			j := i
			for j < n && isIdentChar(src[j]) {
				j++
			}
			word := src[i:j]
			if kw, ok := keywords[strings.ToLower(word)]; ok {
				toks = append(toks, token{kw, word, i})
			} else {
				toks = append(toks, token{tIdent, word, i})
			}
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q at %d", string(c), i)
		}
	}
	toks = append(toks, token{tEOF, "", n})
	return toks, nil
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '.' || c == '-'
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
