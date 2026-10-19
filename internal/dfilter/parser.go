package dfilter

import (
	"strings"
)

type nodeKind uint8

const (
	nAnd nodeKind = iota
	nOr
	nXor
	nNot
	nCompare // op: tEq, tNe, ...
	nIn      // left in set
	nNotIn
	nExists // bare value: field presence / non-zero
	nWord   // field or unparsed literal (resolved during compile)
	nString
	nChar
	nSlice // child[0] sliced by ranges
	nLayer // child[0] restricted to layers
	nRaw   // @field
	nRef   // ${field}
	nFunc
	nArith // op: tPlus, tMinus, tStar, tSlash, tPercent
	nNeg
	nSet
	nRange // in set: lo..hi
)

// rng is a slice or layer range: n items starting at start (negative start
// counts from the end; n < 0 means "to the end").
type rng struct {
	start int
	n     int
}

type node struct {
	kind  nodeKind
	op    tokKind
	quant tokKind // tAny / tAll / 0
	val   string
	raw   bool
	pos   int
	end   int
	kids  []*node
	rngs  []rng
}

type parser struct {
	src  string
	toks []token
	i    int
}

func parse(src string) (*node, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{src: src, toks: toks}
	if p.peek().kind == tEOF {
		return nil, nil
	}
	n, err := p.orExpr()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tEOF {
		return nil, errAt(t.pos, t.end-t.pos, "Unexpected %s \"%s\"", describe(t), p.src[t.pos:t.end])
	}
	return n, nil
}

func describe(t token) string {
	switch t.kind {
	case tWord:
		return "word"
	case tString:
		return "string"
	}
	return "token"
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}

func (p *parser) expect(k tokKind, what string) (token, error) {
	t := p.peek()
	if t.kind != k {
		if t.kind == tEOF {
			return t, errAt(t.pos, 0, "Missing %s", what)
		}
		return t, errAt(t.pos, t.end-t.pos, "Expected %s but found \"%s\"", what, p.src[t.pos:t.end])
	}
	return p.next(), nil
}

func (p *parser) binary(next func() (*node, error), ops map[tokKind]nodeKind) (*node, error) {
	left, err := next()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		k, ok := ops[t.kind]
		if !ok {
			return left, nil
		}
		p.next()
		right, err := next()
		if err != nil {
			return nil, err
		}
		if right == nil {
			return nil, errAt(t.pos, t.end-t.pos, "Missing expression after %s", t.kind)
		}
		left = &node{kind: k, op: t.kind, pos: left.pos, end: right.end, kids: []*node{left, right}}
	}
}

func (p *parser) orExpr() (*node, error) {
	return p.binary(p.xorExpr, map[tokKind]nodeKind{tOr: nOr})
}

func (p *parser) xorExpr() (*node, error) {
	return p.binary(p.andExpr, map[tokKind]nodeKind{tXor: nXor})
}

func (p *parser) andExpr() (*node, error) {
	return p.binary(p.notExpr, map[tokKind]nodeKind{tAnd: nAnd})
}

func (p *parser) notExpr() (*node, error) {
	if t := p.peek(); t.kind == tNot {
		p.next()
		child, err := p.notExpr()
		if err != nil {
			return nil, err
		}
		return &node{kind: nNot, pos: t.pos, end: child.end, kids: []*node{child}}, nil
	}
	return p.relation()
}

func isRelOp(k tokKind) bool {
	switch k {
	case tEq, tNe, tAllEq, tAnyNe, tGt, tGe, tLt, tLe, tContains, tMatches, tBitAnd:
		return true
	}
	return false
}

func (p *parser) relation() (*node, error) {
	start := p.peek()
	var quant tokKind
	if start.kind == tAny || start.kind == tAll {
		quant = start.kind
		p.next()
	}
	if t := p.peek(); t.kind == tLParen && quant == 0 {
		p.next()
		inner, err := p.orExpr()
		if err != nil {
			return nil, err
		}
		if inner == nil {
			return nil, errAt(t.pos, 1, "Empty parentheses")
		}
		closeTok, err := p.expect(tRParen, "\")\"")
		if err != nil {
			return nil, err
		}
		inner.pos, inner.end = t.pos, closeTok.end
		return inner, nil
	}
	left, err := p.arith()
	if err != nil {
		return nil, err
	}
	t := p.peek()
	switch {
	case isRelOp(t.kind):
		p.next()
		right, err := p.arith()
		if err != nil {
			return nil, err
		}
		return &node{kind: nCompare, op: t.kind, quant: quant, pos: start.pos, end: right.end, kids: []*node{left, right}}, nil
	case t.kind == tIn || (t.kind == tNot && p.toks[p.i+1].kind == tIn):
		kind := nIn
		if t.kind == tNot {
			kind = nNotIn
			p.next()
		}
		p.next()
		set, err := p.set()
		if err != nil {
			return nil, err
		}
		return &node{kind: kind, quant: quant, pos: start.pos, end: set.end, kids: []*node{left, set}}, nil
	}
	if quant != 0 {
		return nil, errAt(start.pos, start.end-start.pos, "\"%s\" must be followed by a comparison", start.val)
	}
	return &node{kind: nExists, pos: left.pos, end: left.end, kids: []*node{left}}, nil
}

func (p *parser) set() (*node, error) {
	open, err := p.expect(tLBrace, "\"{\" to start a set")
	if err != nil {
		return nil, err
	}
	s := &node{kind: nSet, pos: open.pos}
	for {
		t := p.peek()
		if t.kind == tRBrace {
			p.next()
			s.end = t.end
			if len(s.kids) == 0 {
				return nil, errAt(open.pos, t.end-open.pos, "Empty set")
			}
			return s, nil
		}
		if t.kind == tEOF {
			return nil, errAt(open.pos, t.pos-open.pos, "Missing \"}\" to close the set")
		}
		if t.kind == tComma {
			p.next()
			continue
		}
		lo, err := p.arith()
		if err != nil {
			return nil, err
		}
		if p.peek().kind == tDotDot {
			p.next()
			hi, err := p.arith()
			if err != nil {
				return nil, err
			}
			s.kids = append(s.kids, &node{kind: nRange, pos: lo.pos, end: hi.end, kids: []*node{lo, hi}})
			continue
		}
		// "1..10" lexes as a word when written without spaces.
		if lo.kind == nWord && strings.Contains(lo.val, "..") {
			parts := strings.SplitN(lo.val, "..", 2)
			a := &node{kind: nWord, val: parts[0], pos: lo.pos, end: lo.pos + len(parts[0])}
			b := &node{kind: nWord, val: parts[1], pos: lo.end - len(parts[1]), end: lo.end}
			s.kids = append(s.kids, &node{kind: nRange, pos: lo.pos, end: lo.end, kids: []*node{a, b}})
			continue
		}
		s.kids = append(s.kids, lo)
	}
}

func (p *parser) arith() (*node, error) {
	return p.arithLevel(0)
}

var arithLevels = []map[tokKind]bool{
	{tPlus: true, tMinus: true},
	{tStar: true, tSlash: true, tPercent: true},
}

func (p *parser) arithLevel(level int) (*node, error) {
	if level == len(arithLevels) {
		return p.unary()
	}
	left, err := p.arithLevel(level + 1)
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if !arithLevels[level][t.kind] {
			return left, nil
		}
		p.next()
		right, err := p.arithLevel(level + 1)
		if err != nil {
			return nil, err
		}
		left = &node{kind: nArith, op: t.kind, pos: left.pos, end: right.end, kids: []*node{left, right}}
	}
}

func (p *parser) unary() (*node, error) {
	t := p.peek()
	if t.kind == tMinus {
		p.next()
		child, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &node{kind: nNeg, pos: t.pos, end: child.end, kids: []*node{child}}, nil
	}
	return p.postfix()
}

func (p *parser) postfix() (*node, error) {
	n, err := p.primary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		switch t.kind {
		case tSlice:
			p.next()
			rngs, err := parseRanges(t.val, t.pos+1)
			if err != nil {
				return nil, err
			}
			n = &node{kind: nSlice, pos: n.pos, end: t.end, kids: []*node{n}, rngs: rngs}
		case tHash:
			p.next()
			lt := p.peek()
			var spec string
			var end int
			switch lt.kind {
			case tWord:
				p.next()
				spec, end = lt.val, lt.end
			case tSlice:
				p.next()
				spec, end = lt.val, lt.end
			default:
				return nil, errAt(t.pos, 1, "Expected a layer number after \"#\"")
			}
			rngs, err := parseRanges(spec, lt.pos)
			if err != nil {
				return nil, err
			}
			n = &node{kind: nLayer, pos: n.pos, end: end, kids: []*node{n}, rngs: rngs}
		default:
			return n, nil
		}
	}
}

func (p *parser) primary() (*node, error) {
	t := p.next()
	switch t.kind {
	case tWord:
		if p.peek().kind == tLParen && isFuncName(t.val) {
			return p.call(t)
		}
		return &node{kind: nWord, val: t.val, pos: t.pos, end: t.end}, nil
	case tString:
		return &node{kind: nString, val: t.val, raw: t.raw, pos: t.pos, end: t.end}, nil
	case tChar:
		return &node{kind: nChar, val: t.val, pos: t.pos, end: t.end}, nil
	case tRef:
		return &node{kind: nRef, val: t.val, pos: t.pos, end: t.end}, nil
	case tAt:
		w := p.next()
		if w.kind != tWord {
			return nil, errAt(t.pos, 1, "Expected a field name after \"@\"")
		}
		return &node{kind: nRaw, val: w.val, pos: t.pos, end: w.end}, nil
	case tLBrace:
		// Arithmetic grouping: { a + b }.
		inner, err := p.arith()
		if err != nil {
			return nil, err
		}
		closeTok, err := p.expect(tRBrace, "\"}\"")
		if err != nil {
			return nil, err
		}
		inner.pos, inner.end = t.pos, closeTok.end
		return inner, nil
	case tEOF:
		return nil, errAt(t.pos, 0, "Unexpected end of filter")
	}
	return nil, errAt(t.pos, t.end-t.pos, "Unexpected \"%s\"", p.src[t.pos:t.end])
}

func (p *parser) call(name token) (*node, error) {
	p.next() // (
	n := &node{kind: nFunc, val: strings.ToLower(name.val), pos: name.pos}
	if p.peek().kind == tRParen {
		n.end = p.next().end
		return n, nil
	}
	for {
		arg, err := p.arith()
		if err != nil {
			return nil, err
		}
		n.kids = append(n.kids, arg)
		t := p.next()
		if t.kind == tRParen {
			n.end = t.end
			return n, nil
		}
		if t.kind != tComma {
			return nil, errAt(t.pos, t.end-t.pos, "Expected \",\" or \")\" in function call")
		}
	}
}

// parseRanges parses slice/layer specs: "0:3", "1-3", "4", ":2", "-2:", "1,3-4".
func parseRanges(spec string, pos int) ([]rng, error) {
	var out []rng
	bad := func(part string) error {
		return errAt(pos, len(spec), "\"%s\" is not a valid range", part)
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errAt(pos, len(spec), "Empty range")
		}
		var r rng
		switch {
		case strings.Contains(part, ":"):
			a, b, _ := strings.Cut(part, ":")
			from, ok := atoiOpt(a, 0)
			if !ok {
				return nil, bad(part)
			}
			r.start, r.n = from, -1
			if b != "" {
				n, ok := atoiOpt(b, 0)
				if !ok || n < 0 {
					return nil, bad(part)
				}
				r.n = n
			}
		case strings.Count(part, "-") == 1 && !strings.HasPrefix(part, "-"):
			a, b, _ := strings.Cut(part, "-")
			from, ok1 := atoiOpt(a, 0)
			to, ok2 := atoiOpt(b, 0)
			if !ok1 || !ok2 || to < from {
				return nil, bad(part)
			}
			r.start, r.n = from, to-from+1
		default:
			n, ok := atoiOpt(part, 0)
			if !ok {
				return nil, bad(part)
			}
			r.start, r.n = n, 1
		}
		out = append(out, r)
	}
	return out, nil
}

func atoiOpt(s string, def int) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, true
	}
	neg := false
	if s[0] == '-' {
		neg, s = true, s[1:]
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > 1<<24 {
			return 0, false
		}
	}
	if neg {
		n = -n
	}
	return n, true
}
