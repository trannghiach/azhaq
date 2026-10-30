package probefilter

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Expr is a condition over a row's fields for -mdc and -fdc: the subset of
// httpx's DSL a reviewer uses on a result, such as
// contains(body, "admin") && status_code == 200. Names are the fields of
// -json; an unknown name or function is an error, never a silent false.
type Expr struct {
	src  string
	root node
}

type node interface {
	eval(vars map[string]any) (any, error)
}

// Compile parses a condition.
func Compile(flag, src string) (*Expr, error) {
	p := &parser{src: src}
	if err := p.lex(); err != nil {
		return nil, fmt.Errorf("%s: %w", flag, err)
	}
	n, err := p.or()
	if err == nil && p.i < len(p.toks) {
		err = fmt.Errorf("unexpected %q", p.toks[p.i].s)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", flag, src, err)
	}
	return &Expr{src: src, root: n}, nil
}

// Eval is the condition's truth for the fields.
func (e *Expr) Eval(vars map[string]any) (bool, error) {
	v, err := e.root.eval(vars)
	if err != nil {
		return false, fmt.Errorf("condition %q: %w", e.src, err)
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("condition %q is not true or false", e.src)
	}
	return b, nil
}

type tok struct {
	kind byte // n number, s string, i ident, o operator
	s    string
}

type parser struct {
	src  string
	toks []tok
	i    int
}

func (p *parser) lex() error {
	s := p.src
	for i := 0; i < len(s); {
		c := rune(s[i])
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '"' || c == '\'' || c == '`':
			j := i + 1
			var b strings.Builder
			for j < len(s) && rune(s[j]) != c {
				if s[j] == '\\' && c != '`' && j+1 < len(s) {
					j++
					switch s[j] {
					case 'n':
						b.WriteByte('\n')
					case 't':
						b.WriteByte('\t')
					case 'r':
						b.WriteByte('\r')
					default:
						b.WriteByte(s[j])
					}
				} else {
					b.WriteByte(s[j])
				}
				j++
			}
			if j >= len(s) {
				return fmt.Errorf("unterminated string")
			}
			p.toks = append(p.toks, tok{'s', b.String()})
			i = j + 1
		case unicode.IsDigit(c):
			j := i
			for j < len(s) && (unicode.IsDigit(rune(s[j])) || s[j] == '.') {
				j++
			}
			p.toks = append(p.toks, tok{'n', s[i:j]})
			i = j
		case unicode.IsLetter(c) || c == '_':
			j := i
			for j < len(s) && (unicode.IsLetter(rune(s[j])) || unicode.IsDigit(rune(s[j])) || s[j] == '_') {
				j++
			}
			p.toks = append(p.toks, tok{'i', s[i:j]})
			i = j
		default:
			two := ""
			if i+1 < len(s) {
				two = s[i : i+2]
			}
			switch two {
			case "&&", "||", "==", "!=", "<=", ">=", "=~", "!~":
				p.toks = append(p.toks, tok{'o', two})
				i += 2
				continue
			}
			if strings.ContainsRune("()+-*/%<>!,", c) {
				p.toks = append(p.toks, tok{'o', string(c)})
				i++
				continue
			}
			return fmt.Errorf("unexpected %q", string(c))
		}
	}
	return nil
}

func (p *parser) peek(ops ...string) (string, bool) {
	if p.i >= len(p.toks) || p.toks[p.i].kind != 'o' {
		return "", false
	}
	for _, o := range ops {
		if p.toks[p.i].s == o {
			return o, true
		}
	}
	return "", false
}

type binary struct {
	op   string
	l, r node
}

type unary struct {
	op string
	x  node
}

type lit struct{ v any }

type name struct{ n string }

type call struct {
	fn   string
	args []node
}

func (p *parser) level(next func() (node, error), ops ...string) (node, error) {
	l, err := next()
	if err != nil {
		return nil, err
	}
	for {
		op, ok := p.peek(ops...)
		if !ok {
			return l, nil
		}
		p.i++
		r, err := next()
		if err != nil {
			return nil, err
		}
		l = &binary{op, l, r}
	}
}

func (p *parser) or() (node, error)  { return p.level(p.and, "||") }
func (p *parser) and() (node, error) { return p.level(p.eq, "&&") }
func (p *parser) eq() (node, error)  { return p.level(p.cmp, "==", "!=", "=~", "!~") }
func (p *parser) cmp() (node, error) { return p.level(p.add, "<", ">", "<=", ">=") }
func (p *parser) add() (node, error) { return p.level(p.mul, "+", "-") }
func (p *parser) mul() (node, error) { return p.level(p.un, "*", "/", "%") }

func (p *parser) un() (node, error) {
	if op, ok := p.peek("!", "-"); ok {
		p.i++
		x, err := p.un()
		if err != nil {
			return nil, err
		}
		return &unary{op, x}, nil
	}
	return p.atom()
}

func (p *parser) atom() (node, error) {
	if p.i >= len(p.toks) {
		return nil, fmt.Errorf("the condition ends early")
	}
	t := p.toks[p.i]
	p.i++
	switch t.kind {
	case 'n':
		f, err := strconv.ParseFloat(t.s, 64)
		if err != nil {
			return nil, fmt.Errorf("bad number %q", t.s)
		}
		return &lit{f}, nil
	case 's':
		return &lit{t.s}, nil
	case 'i':
		switch t.s {
		case "true":
			return &lit{true}, nil
		case "false":
			return &lit{false}, nil
		}
		if _, ok := p.peek("("); ok {
			p.i++
			c := &call{fn: t.s}
			if _, ok := p.peek(")"); ok {
				p.i++
				return c, nil
			}
			for {
				a, err := p.or()
				if err != nil {
					return nil, err
				}
				c.args = append(c.args, a)
				if _, ok := p.peek(","); ok {
					p.i++
					continue
				}
				if _, ok := p.peek(")"); ok {
					p.i++
					return c, nil
				}
				return nil, fmt.Errorf("want , or ) in %s(", t.s)
			}
		}
		return &name{t.s}, nil
	case 'o':
		if t.s == "(" {
			n, err := p.or()
			if err != nil {
				return nil, err
			}
			if _, ok := p.peek(")"); !ok {
				return nil, fmt.Errorf("missing )")
			}
			p.i++
			return n, nil
		}
	}
	return nil, fmt.Errorf("unexpected %q", t.s)
}

func (l *lit) eval(map[string]any) (any, error) { return l.v, nil }

func (n *name) eval(vars map[string]any) (any, error) {
	v, ok := vars[n.n]
	if !ok {
		return nil, fmt.Errorf("unknown field %q", n.n)
	}
	return norm(v), nil
}

// norm turns a field into a string, a number, a bool or a list.
func norm(v any) any {
	switch x := v.(type) {
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	}
	return v
}

func (u *unary) eval(vars map[string]any) (any, error) {
	v, err := u.x.eval(vars)
	if err != nil {
		return nil, err
	}
	switch u.op {
	case "!":
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("! wants true or false")
		}
		return !b, nil
	default:
		f, ok := v.(float64)
		if !ok {
			return nil, fmt.Errorf("- wants a number")
		}
		return -f, nil
	}
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = str(e)
		}
		return strings.Join(parts, ",")
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func (b *binary) eval(vars map[string]any) (any, error) {
	l, err := b.l.eval(vars)
	if err != nil {
		return nil, err
	}
	if b.op == "&&" || b.op == "||" {
		lb, ok := l.(bool)
		if !ok {
			return nil, fmt.Errorf("%s wants true or false", b.op)
		}
		if b.op == "&&" && !lb {
			return false, nil
		}
		if b.op == "||" && lb {
			return true, nil
		}
		r, err := b.r.eval(vars)
		if err != nil {
			return nil, err
		}
		rb, ok := r.(bool)
		if !ok {
			return nil, fmt.Errorf("%s wants true or false", b.op)
		}
		return rb, nil
	}
	r, err := b.r.eval(vars)
	if err != nil {
		return nil, err
	}
	lf, lok := l.(float64)
	rf, rok := r.(float64)
	switch b.op {
	case "==":
		if lok && rok {
			return lf == rf, nil
		}
		return str(l) == str(r), nil
	case "!=":
		if lok && rok {
			return lf != rf, nil
		}
		return str(l) != str(r), nil
	case "=~", "!~":
		re, err := regexp.Compile(str(r))
		if err != nil {
			return nil, err
		}
		return re.MatchString(str(l)) == (b.op == "=~"), nil
	case "+":
		if lok && rok {
			return lf + rf, nil
		}
		return str(l) + str(r), nil
	}
	if !lok || !rok {
		return nil, fmt.Errorf("%s wants numbers", b.op)
	}
	switch b.op {
	case "<":
		return lf < rf, nil
	case ">":
		return lf > rf, nil
	case "<=":
		return lf <= rf, nil
	case ">=":
		return lf >= rf, nil
	case "-":
		return lf - rf, nil
	case "*":
		return lf * rf, nil
	case "/":
		if rf == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		return lf / rf, nil
	case "%":
		if int(rf) == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		return float64(int(lf) % int(rf)), nil
	}
	return nil, fmt.Errorf("unknown operator %s", b.op)
}

func (c *call) eval(vars map[string]any) (any, error) {
	args := make([]any, len(c.args))
	for i, a := range c.args {
		v, err := a.eval(vars)
		if err != nil {
			return nil, err
		}
		args[i] = v
	}
	need := func(n int) error {
		if len(args) < n {
			return fmt.Errorf("%s wants %d arguments", c.fn, n)
		}
		return nil
	}
	s := func(i int) string { return str(args[i]) }
	sum := func(f func([]byte) []byte) (any, error) {
		if err := need(1); err != nil {
			return nil, err
		}
		return hex.EncodeToString(f([]byte(s(0)))), nil
	}
	switch c.fn {
	case "contains":
		if err := need(2); err != nil {
			return nil, err
		}
		return strings.Contains(s(0), s(1)), nil
	case "contains_any", "contains_all":
		if err := need(2); err != nil {
			return nil, err
		}
		hits := 0
		for _, x := range args[1:] {
			if strings.Contains(s(0), str(x)) {
				hits++
			}
		}
		if c.fn == "contains_any" {
			return hits > 0, nil
		}
		return hits == len(args)-1, nil
	case "starts_with", "ends_with":
		if err := need(2); err != nil {
			return nil, err
		}
		for _, x := range args[1:] {
			if c.fn == "starts_with" && strings.HasPrefix(s(0), str(x)) || c.fn == "ends_with" && strings.HasSuffix(s(0), str(x)) {
				return true, nil
			}
		}
		return false, nil
	case "regex":
		if err := need(2); err != nil {
			return nil, err
		}
		re, err := regexp.Compile(s(0))
		if err != nil {
			return nil, err
		}
		return re.MatchString(s(1)), nil
	case "equals":
		if err := need(2); err != nil {
			return nil, err
		}
		return s(0) == s(1), nil
	case "to_lower", "tolower":
		if err := need(1); err != nil {
			return nil, err
		}
		return strings.ToLower(s(0)), nil
	case "to_upper", "toupper":
		if err := need(1); err != nil {
			return nil, err
		}
		return strings.ToUpper(s(0)), nil
	case "trim", "trim_space":
		if err := need(1); err != nil {
			return nil, err
		}
		if len(args) > 1 {
			return strings.Trim(s(0), s(1)), nil
		}
		return strings.TrimSpace(s(0)), nil
	case "len":
		if err := need(1); err != nil {
			return nil, err
		}
		if l, ok := args[0].([]any); ok {
			return float64(len(l)), nil
		}
		return float64(len(s(0))), nil
	case "replace":
		if err := need(3); err != nil {
			return nil, err
		}
		return strings.ReplaceAll(s(0), s(1), s(2)), nil
	case "to_number":
		if err := need(1); err != nil {
			return nil, err
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(s(0)), 64)
		if err != nil {
			return nil, err
		}
		return f, nil
	case "to_string":
		if err := need(1); err != nil {
			return nil, err
		}
		return s(0), nil
	case "md5":
		return sum(func(b []byte) []byte { h := md5.Sum(b); return h[:] })
	case "sha1":
		return sum(func(b []byte) []byte { h := sha1.Sum(b); return h[:] })
	case "sha256":
		return sum(func(b []byte) []byte { h := sha256.Sum256(b); return h[:] })
	case "base64":
		if err := need(1); err != nil {
			return nil, err
		}
		return base64.StdEncoding.EncodeToString([]byte(s(0))), nil
	case "base64_decode":
		if err := need(1); err != nil {
			return nil, err
		}
		b, err := base64.StdEncoding.DecodeString(s(0))
		return string(b), err
	case "url_encode":
		if err := need(1); err != nil {
			return nil, err
		}
		return url.QueryEscape(s(0)), nil
	case "url_decode":
		if err := need(1); err != nil {
			return nil, err
		}
		return url.QueryUnescape(s(0))
	}
	return nil, fmt.Errorf("unknown function %s", c.fn)
}
