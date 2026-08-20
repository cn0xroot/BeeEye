// Package dfilter implements the analyzer's display-filter language.
//
// The syntax is a deliberate subset of Wireshark's, because that is the syntax
// people already know:
//
//	tcp.port == 443 && !mdns
//	ip.addr == 192.168.1.0/24 and dns.qry.name contains "tuya"
//	tls.handshake.extensions_server_name matches "^ota\."
//	dns.flags.rcode == 3 || (tcp.flags.syn == 1 && tcp.flags.ack == 0)
//
// Supported: && || ! and or not, parentheses, == != > < >= <=, contains,
// matches (regexp), CIDR on address fields, and a bare protocol name as a
// presence test.
//
// One deliberate divergence: `a != b` means "no value of a equals b". In
// Wireshark it means "some value differs", which surprises people on
// multi-value fields like tcp.port — there, `tcp.port != 443` is true for
// every packet, since the other endpoint's port is never 443. The behaviour
// here is the one users expect; `!(a == b)` means the same thing.
package dfilter

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Target is what an expression is evaluated against: a flat multi-valued field
// index plus the set of protocol keys present in the packet.
type Target interface {
	FieldValues(name string) []string
	HasProtocol(name string) bool
}

// Expr is a compiled filter. The zero value matches everything.
type Expr struct {
	root nodeExpr
	src  string
}

// String returns the original filter text.
func (e *Expr) String() string {
	if e == nil {
		return ""
	}
	return e.src
}

// Match reports whether t satisfies the filter. A nil or empty filter matches
// every packet, which is what an empty filter box should mean.
func (e *Expr) Match(t Target) bool {
	if e == nil || e.root == nil {
		return true
	}
	return e.root.eval(t)
}

// Compile parses filter text. An empty string yields a match-everything Expr.
func Compile(s string) (*Expr, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return &Expr{src: ""}, nil
	}
	toks, err := lex(trimmed)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if !p.done() {
		return nil, fmt.Errorf("unexpected %q at position %d", p.peek().text, p.peek().pos)
	}
	return &Expr{root: root, src: trimmed}, nil
}

// ------------------------------------------------------------------- lexing

type tokKind int

const (
	tokIdent tokKind = iota
	tokString
	tokOp
	tokLParen
	tokRParen
)

type token struct {
	kind tokKind
	text string
	pos  int
}

var multiCharOps = []string{"==", "!=", ">=", "<=", "&&", "||"}

func lex(s string) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '(':
			out = append(out, token{tokLParen, "(", i})
			i++
		case c == ')':
			out = append(out, token{tokRParen, ")", i})
			i++
		case c == '"' || c == '\'':
			quote := c
			j := i + 1
			var sb strings.Builder
			for j < len(s) && s[j] != quote {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				sb.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("unterminated string starting at position %d", i)
			}
			out = append(out, token{tokString, sb.String(), i})
			i = j + 1
		default:
			if op := matchOp(s[i:]); op != "" {
				out = append(out, token{tokOp, op, i})
				i += len(op)
				continue
			}
			if c == '!' || c == '>' || c == '<' {
				out = append(out, token{tokOp, string(c), i})
				i++
				continue
			}
			j := i
			for j < len(s) && isIdentRune(rune(s[j])) {
				j++
			}
			if j == i {
				return nil, fmt.Errorf("unexpected character %q at position %d", string(c), i)
			}
			out = append(out, token{tokIdent, s[i:j], i})
			i = j
		}
	}
	return out, nil
}

func matchOp(s string) string {
	for _, op := range multiCharOps {
		if strings.HasPrefix(s, op) {
			return op
		}
	}
	return ""
}

// Identifier runes cover field names (ip.src), values (192.168.1.0/24,
// aa:bb:cc:dd:ee:ff, 0x1301) and bare words, so unquoted values mostly work.
func isIdentRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) ||
		strings.ContainsRune("._-:/*?+^$\\", r)
}

// ------------------------------------------------------------------ parsing

type nodeExpr interface{ eval(Target) bool }

type orNode struct{ l, r nodeExpr }
type andNode struct{ l, r nodeExpr }
type notNode struct{ x nodeExpr }

func (n orNode) eval(t Target) bool  { return n.l.eval(t) || n.r.eval(t) }
func (n andNode) eval(t Target) bool { return n.l.eval(t) && n.r.eval(t) }
func (n notNode) eval(t Target) bool { return !n.x.eval(t) }

type presenceNode struct{ name string }

func (n presenceNode) eval(t Target) bool {
	return t.HasProtocol(n.name) || len(t.FieldValues(n.name)) > 0
}

type parser struct {
	toks []token
	i    int
}

func (p *parser) done() bool { return p.i >= len(p.toks) }
func (p *parser) peek() token {
	if p.done() {
		return token{tokIdent, "", -1}
	}
	return p.toks[p.i]
}
func (p *parser) next() token { t := p.peek(); p.i++; return t }

func (p *parser) acceptOp(names ...string) bool {
	t := p.peek()
	if t.kind != tokOp && t.kind != tokIdent {
		return false
	}
	for _, n := range names {
		if strings.EqualFold(t.text, n) {
			p.i++
			return true
		}
	}
	return false
}

func (p *parser) parseOr() (nodeExpr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.acceptOp("||", "or") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (nodeExpr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.acceptOp("&&", "and") {
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = andNode{left, right}
	}
	return left, nil
}

func (p *parser) parseNot() (nodeExpr, error) {
	if p.acceptOp("!", "not") {
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return notNode{x}, nil
	}
	return p.parsePrimary()
}

// isComparisonOp reports whether tok starts a comparison. The logical
// operators are deliberately excluded so they terminate a presence test.
func isComparisonOp(tok token) bool {
	switch tok.kind {
	case tokOp:
		switch tok.text {
		case "==", "!=", ">", "<", ">=", "<=":
			return true
		}
	case tokIdent:
		return strings.EqualFold(tok.text, "contains") || strings.EqualFold(tok.text, "matches")
	}
	return false
}

func (p *parser) parsePrimary() (nodeExpr, error) {
	if p.done() {
		return nil, fmt.Errorf("unexpected end of filter: expected a field name or '('")
	}
	t := p.peek()
	if t.kind == tokLParen {
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("missing ')' after expression at position %d", t.pos)
		}
		p.next()
		return inner, nil
	}
	if t.kind != tokIdent {
		return nil, fmt.Errorf("expected a field name, found %q at position %d", t.text, t.pos)
	}
	field := p.next().text

	// A bare identifier is a presence test: `dns`, `tls`, `arp`. Only an
	// actual comparison operator turns it into a comparison — `tls || dns`
	// must not read `||` as one.
	nt := p.peek()
	if !isComparisonOp(nt) {
		return presenceNode{strings.ToLower(field)}, nil
	}

	op := p.next().text
	if p.done() {
		return nil, fmt.Errorf("expected a value after %q at position %d", op, nt.pos)
	}
	vt := p.peek()
	if vt.kind != tokIdent && vt.kind != tokString {
		return nil, fmt.Errorf("expected a value after %q at position %d", op, nt.pos)
	}
	value := p.next().text

	cmp := &compareNode{field: field, op: strings.ToLower(op), value: value}
	if cmp.op == "matches" {
		re, err := regexp.Compile(value)
		if err != nil {
			return nil, fmt.Errorf("bad regular expression %q: %w", value, err)
		}
		cmp.re = re
	}
	if pfx, err := netip.ParsePrefix(value); err == nil {
		cmp.prefix = &pfx
	}
	if n, err := strconv.ParseFloat(value, 64); err == nil {
		cmp.num = &n
	}
	return cmp, nil
}

// --------------------------------------------------------------- comparison

type compareNode struct {
	field  string
	op     string
	value  string
	re     *regexp.Regexp
	prefix *netip.Prefix
	num    *float64
}

func (c *compareNode) eval(t Target) bool {
	values := t.FieldValues(c.field)
	if len(values) == 0 {
		return false // an absent field never satisfies a comparison
	}
	anyMatch := false
	for _, v := range values {
		if c.matchOne(v) {
			anyMatch = true
			break
		}
	}
	if c.op == "!=" {
		return !anyMatch
	}
	return anyMatch
}

func (c *compareNode) matchOne(v string) bool {
	switch c.op {
	case "contains":
		return strings.Contains(strings.ToLower(v), strings.ToLower(c.value))
	case "matches":
		return c.re != nil && c.re.MatchString(v)
	}

	// CIDR membership, so `ip.addr == 10.0.0.0/8` works on address fields.
	if c.prefix != nil {
		if addr, err := netip.ParseAddr(v); err == nil {
			return c.prefix.Contains(addr)
		}
		return false
	}

	// Numeric comparison when both sides are numbers; otherwise fall back to
	// case-insensitive string equality (MACs, domains, protocol names).
	if c.num != nil {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			switch c.op {
			case "==", "!=":
				return n == *c.num
			case ">":
				return n > *c.num
			case "<":
				return n < *c.num
			case ">=":
				return n >= *c.num
			case "<=":
				return n <= *c.num
			}
		}
	}

	switch c.op {
	case "==", "!=":
		return strings.EqualFold(v, c.value)
	case ">":
		return v > c.value
	case "<":
		return v < c.value
	case ">=":
		return v >= c.value
	case "<=":
		return v <= c.value
	}
	return false
}
