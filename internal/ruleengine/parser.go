package ruleengine

import (
	"fmt"
	"strconv"
	"strings"
)

// pred is a compiled boolean predicate over an evaluation context.
type pred func(*evalCtx) bool

// compileCondition lexes, parses, and compiles a DSL condition string into a
// single predicate closure, resolving $list references against lists.
func compileCondition(src string, lists map[string][]string) (pred, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, lists: lists}
	pr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.cur().kind != tEOF {
		return nil, fmt.Errorf("unexpected trailing token %q", p.cur().text)
	}
	return pr, nil
}

type parser struct {
	toks  []token
	pos   int
	lists map[string][]string
}

func (p *parser) cur() token  { return p.toks[p.pos] }
func (p *parser) peek() token { if p.pos+1 < len(p.toks) { return p.toks[p.pos+1] }; return p.toks[len(p.toks)-1] }
func (p *parser) adv()        { if p.pos < len(p.toks)-1 { p.pos++ } }

func (p *parser) expect(k tokKind) error {
	if p.cur().kind != k {
		return fmt.Errorf("expected token %d, got %q", k, p.cur().text)
	}
	p.adv()
	return nil
}

func (p *parser) parseOr() (pred, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.cur().kind == tOr {
		p.adv()
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		a, b := l, r
		l = func(cx *evalCtx) bool { return a(cx) || b(cx) }
	}
	return l, nil
}

func (p *parser) parseAnd() (pred, error) {
	l, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.cur().kind == tAnd {
		p.adv()
		r, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		a, b := l, r
		l = func(cx *evalCtx) bool { return a(cx) && b(cx) }
	}
	return l, nil
}

func (p *parser) parseUnary() (pred, error) {
	if p.cur().kind == tNot {
		p.adv()
		c, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return func(cx *evalCtx) bool { return !c(cx) }, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (pred, error) {
	t := p.cur()
	switch t.kind {
	case tLParen:
		p.adv()
		e, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(tRParen); err != nil {
			return nil, err
		}
		return e, nil
	case tIdent:
		if p.peek().kind == tLParen {
			return p.parseCall(t.text)
		}
		p.adv() // consume the identifier (field name or bare atom)
		switch p.cur().kind {
		case tEq, tNeq, tAmp, tIn, tContains, tStartswith:
			return p.parseComparison(t.text)
		default:
			if _, ok := boolFields[t.text]; ok {
				name := t.text
				return func(cx *evalCtx) bool { return boolFields[name](cx) }, nil
			}
			if t.text == "is_trusted_writer" {
				return func(cx *evalCtx) bool { return cx.c.TrustedWriter(cx.chain()) }, nil
			}
			return nil, fmt.Errorf("unexpected identifier %q (not a boolean field and not followed by an operator)", t.text)
		}
	default:
		return nil, fmt.Errorf("unexpected token %q", t.text)
	}
}

func (p *parser) parseComparison(field string) (pred, error) {
	op := p.cur().kind
	p.adv()

	sf, isStr := strFields[field]
	intf, isInt := intFields[field]
	if !isStr && !isInt {
		return nil, fmt.Errorf("unknown field %q", field)
	}

	switch op {
	case tEq, tNeq:
		if isStr {
			want, err := p.scalarString()
			if err != nil {
				return nil, err
			}
			if op == tEq {
				return func(cx *evalCtx) bool { return sf(cx) == want }, nil
			}
			return func(cx *evalCtx) bool { return sf(cx) != want }, nil
		}
		want, err := p.scalarInt()
		if err != nil {
			return nil, err
		}
		if op == tEq {
			return func(cx *evalCtx) bool { return intf(cx) == want }, nil
		}
		return func(cx *evalCtx) bool { return intf(cx) != want }, nil
	case tContains:
		if !isStr {
			return nil, fmt.Errorf("'contains' needs a string field, got %q", field)
		}
		want, err := p.scalarString()
		if err != nil {
			return nil, err
		}
		return func(cx *evalCtx) bool { return strings.Contains(sf(cx), want) }, nil
	case tStartswith:
		if !isStr {
			return nil, fmt.Errorf("'startswith' needs a string field, got %q", field)
		}
		want, err := p.scalarString()
		if err != nil {
			return nil, err
		}
		return func(cx *evalCtx) bool { return strings.HasPrefix(sf(cx), want) }, nil
	case tAmp:
		if !isInt {
			return nil, fmt.Errorf("'&' needs an integer field, got %q", field)
		}
		mask, err := p.scalarInt()
		if err != nil {
			return nil, err
		}
		return func(cx *evalCtx) bool { return intf(cx)&mask != 0 }, nil
	case tIn:
		if isStr {
			items, err := p.listStrings()
			if err != nil {
				return nil, err
			}
			set := loweredSet(items)
			return func(cx *evalCtx) bool { return set[strings.ToLower(sf(cx))] }, nil
		}
		ints, err := p.listInts()
		if err != nil {
			return nil, err
		}
		return func(cx *evalCtx) bool {
			v := intf(cx)
			for _, n := range ints {
				if v == n {
					return true
				}
			}
			return false
		}, nil
	}
	return nil, fmt.Errorf("unsupported operator on field %q", field)
}

func (p *parser) parseCall(name string) (pred, error) {
	p.adv() // ident
	if err := p.expect(tLParen); err != nil {
		return nil, err
	}
	var args []token
	for p.cur().kind != tRParen {
		if p.cur().kind == tEOF {
			return nil, fmt.Errorf("%s: unterminated argument list", name)
		}
		args = append(args, p.cur())
		p.adv()
		if p.cur().kind == tComma {
			p.adv()
		}
	}
	if err := p.expect(tRParen); err != nil {
		return nil, err
	}

	fieldArg := func(i int) (strAccessor, error) {
		if i >= len(args) || args[i].kind != tIdent {
			return nil, fmt.Errorf("%s: expected a field argument", name)
		}
		sf, ok := strFields[args[i].text]
		if !ok {
			return nil, fmt.Errorf("%s: %q is not a string field", name, args[i].text)
		}
		return sf, nil
	}
	listArg := func(i int) ([]string, error) {
		if i >= len(args) || args[i].kind != tList {
			return nil, fmt.Errorf("%s: expected a $list argument", name)
		}
		l, ok := p.lists[args[i].text]
		if !ok {
			return nil, fmt.Errorf("%s: unknown list $%s", name, args[i].text)
		}
		return l, nil
	}

	switch name {
	case "in_list":
		sf, err := fieldArg(0)
		if err != nil {
			return nil, err
		}
		l, err := listArg(1)
		if err != nil {
			return nil, err
		}
		set := loweredSet(l)
		return func(cx *evalCtx) bool { return set[strings.ToLower(sf(cx))] }, nil
	case "chain_in_list":
		l, err := listArg(0)
		if err != nil {
			return nil, err
		}
		set := loweredSet(l)
		return func(cx *evalCtx) bool {
			for _, a := range cx.chain() {
				if set[strings.ToLower(a)] {
					return true
				}
			}
			return false
		}, nil
	case "has_prefix":
		sf, err := fieldArg(0)
		if err != nil {
			return nil, err
		}
		l, err := listArg(1)
		if err != nil {
			return nil, err
		}
		prefixes := append([]string(nil), l...)
		return func(cx *evalCtx) bool {
			s := sf(cx)
			for _, pre := range prefixes {
				if strings.HasPrefix(s, pre) {
					return true
				}
			}
			return false
		}, nil
	case "contains_any":
		sf, err := fieldArg(0)
		if err != nil {
			return nil, err
		}
		l, err := listArg(1)
		if err != nil {
			return nil, err
		}
		subs := append([]string(nil), l...)
		return func(cx *evalCtx) bool {
			s := sf(cx)
			for _, sub := range subs {
				if sub != "" && strings.Contains(s, sub) {
					return true
				}
			}
			return false
		}, nil
	case "is_docker_client":
		sf, err := fieldArg(0)
		if err != nil {
			return nil, err
		}
		return func(cx *evalCtx) bool { return cx.c.IsDockerClient(sf(cx)) }, nil
	case "reverse_shell":
		sf, err := fieldArg(0)
		if err != nil {
			return nil, err
		}
		return func(cx *evalCtx) bool { return reverseShellMatch(sf(cx)) }, nil
	case "is_trusted_writer":
		return func(cx *evalCtx) bool { return cx.c.TrustedWriter(cx.chain()) }, nil
	default:
		return nil, fmt.Errorf("unknown function %q", name)
	}
}

// ── operand parsing ───────────────────────────────────────────────────────────

func (p *parser) scalarString() (string, error) {
	t := p.cur()
	switch t.kind {
	case tString, tIdent:
		p.adv()
		return t.text, nil
	default:
		return "", fmt.Errorf("expected a string operand, got %q", t.text)
	}
}

func (p *parser) scalarInt() (int64, error) {
	t := p.cur()
	if t.kind != tInt {
		return 0, fmt.Errorf("expected an integer operand, got %q", t.text)
	}
	p.adv()
	return strconv.ParseInt(t.text, 0, 64)
}

func (p *parser) listStrings() ([]string, error) {
	t := p.cur()
	if t.kind == tList {
		l, ok := p.lists[t.text]
		if !ok {
			return nil, fmt.Errorf("unknown list $%s", t.text)
		}
		p.adv()
		return l, nil
	}
	if t.kind == tLBrack {
		p.adv()
		var out []string
		for p.cur().kind != tRBrack {
			c := p.cur()
			if c.kind != tString && c.kind != tIdent {
				return nil, fmt.Errorf("expected string in list literal, got %q", c.text)
			}
			out = append(out, c.text)
			p.adv()
			if p.cur().kind == tComma {
				p.adv()
			}
		}
		p.adv() // ]
		return out, nil
	}
	return nil, fmt.Errorf("expected $list or [..] after 'in', got %q", t.text)
}

func (p *parser) listInts() ([]int64, error) {
	if p.cur().kind != tLBrack {
		return nil, fmt.Errorf("expected [..] integer list after 'in', got %q", p.cur().text)
	}
	p.adv()
	var out []int64
	for p.cur().kind != tRBrack {
		v, err := p.scalarInt()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		if p.cur().kind == tComma {
			p.adv()
		}
	}
	p.adv() // ]
	return out, nil
}

func loweredSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[strings.ToLower(it)] = true
	}
	return m
}
