package dfilter

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"

	"github.com/poseydon/lazysniffer/internal/dissect"
)

// Filter is a compiled display filter.
type Filter struct {
	Text string
	// Fields lists every field the filter reads; dissections used for
	// evaluation must record them.
	Fields []*dissect.FieldDef
	// Refs lists fields referenced as ${field} (values of the selected packet).
	Refs     []*dissect.FieldDef
	Warnings []string
	test     testFn
	refVals  map[*dissect.FieldDef][]val
}

type env struct {
	pi   *dissect.PacketInfo
	refs map[*dissect.FieldDef][]val
}

type testFn func(e *env) bool
type valFn func(e *env) []val

type expr struct {
	fn    valFn
	k     kind
	field *dissect.FieldDef // set when the expression is a plain field
}

type compiler struct {
	src    string
	fields map[*dissect.FieldDef]bool
	refs   map[*dissect.FieldDef]bool
	warn   []string
}

// Compile parses and type-checks a display filter. An empty filter matches
// every packet.
func Compile(text string) (*Filter, error) {
	root, err := parse(text)
	if err != nil {
		return nil, err
	}
	f := &Filter{Text: text}
	if root == nil {
		f.test = func(*env) bool { return true }
		return f, nil
	}
	c := &compiler{src: text, fields: map[*dissect.FieldDef]bool{}, refs: map[*dissect.FieldDef]bool{}}
	t, err := c.test(root)
	if err != nil {
		return nil, err
	}
	f.test = t
	for fd := range c.fields {
		f.Fields = append(f.Fields, fd)
	}
	sort.Slice(f.Fields, func(i, j int) bool { return f.Fields[i].ID < f.Fields[j].ID })
	for fd := range c.refs {
		f.Refs = append(f.Refs, fd)
	}
	f.Warnings = c.warn
	return f, nil
}

// Empty reports whether the filter matches everything.
func (f *Filter) Empty() bool { return strings.TrimSpace(f.Text) == "" }

// Want marks the filter's fields in a want vector (indexed by FieldID).
func (f *Filter) Want(want []bool) {
	for _, fd := range f.Fields {
		if int(fd.ID) < len(want) {
			want[fd.ID] = true
		}
	}
}

// SetRefs provides values for ${field} references from a packet dissection.
func (f *Filter) SetRefs(pi *dissect.PacketInfo) {
	f.refVals = map[*dissect.FieldDef][]val{}
	if pi == nil {
		return
	}
	for _, fd := range f.Refs {
		for _, fv := range pi.Tree.Values(fd) {
			f.refVals[fd] = append(f.refVals[fd], fromField(fd, fv.V))
		}
	}
}

// Match evaluates the filter on a dissected packet.
func (f *Filter) Match(pi *dissect.PacketInfo) bool {
	return f.test(&env{pi: pi, refs: f.refVals})
}

func (c *compiler) errNode(n *node, format string, args ...any) *Error {
	return errAt(n.pos, n.end-n.pos, format, args...)
}

func (c *compiler) text(n *node) string { return c.src[n.pos:n.end] }

func (c *compiler) test(n *node) (testFn, error) {
	switch n.kind {
	case nAnd, nOr, nXor:
		a, err := c.test(n.kids[0])
		if err != nil {
			return nil, err
		}
		b, err := c.test(n.kids[1])
		if err != nil {
			return nil, err
		}
		switch n.kind {
		case nAnd:
			return func(e *env) bool { return a(e) && b(e) }, nil
		case nOr:
			return func(e *env) bool { return a(e) || b(e) }, nil
		}
		return func(e *env) bool { return a(e) != b(e) }, nil
	case nNot:
		a, err := c.test(n.kids[0])
		if err != nil {
			return nil, err
		}
		return func(e *env) bool { return !a(e) }, nil
	case nExists:
		return c.exists(n.kids[0])
	case nCompare:
		return c.compare(n)
	case nIn, nNotIn:
		return c.membership(n)
	}
	return nil, c.errNode(n, "\"%s\" is not a valid filter expression", c.text(n))
}

// typed reports whether a node has a type of its own (not a bare literal).
func (c *compiler) typed(n *node) bool {
	switch n.kind {
	case nWord:
		return c.lookup(n.val) != nil
	case nString, nChar:
		return false
	case nArith:
		return c.typed(n.kids[0]) || c.typed(n.kids[1])
	case nNeg:
		return c.typed(n.kids[0])
	}
	return true
}

func (c *compiler) lookup(name string) *dissect.FieldDef {
	if strings.HasPrefix(name, ":") {
		return nil
	}
	name = strings.TrimPrefix(name, ".")
	return dissect.LookupField(name)
}

func (c *compiler) field(n *node) (*dissect.FieldDef, error) {
	f := c.lookup(n.val)
	if f == nil {
		return nil, &Error{Msg: fmt.Sprintf("\"%s\" is not a valid protocol or protocol field.", n.val), Pos: n.pos, Len: n.end - n.pos, Unknown: n.val}
	}
	c.fields[f] = true
	return f, nil
}

func (c *compiler) exists(n *node) (testFn, error) {
	if n.kind == nWord {
		f, err := c.field(n)
		if err != nil {
			return nil, err
		}
		return func(e *env) bool {
			for i := range e.pi.Tree.Vals {
				if e.pi.Tree.Vals[i].F == f {
					return true
				}
			}
			return false
		}, nil
	}
	if !c.typed(n) {
		return nil, c.errNode(n, "\"%s\" is not a valid protocol or protocol field.", c.text(n))
	}
	ex, err := c.value(n, kNone, nil)
	if err != nil {
		return nil, err
	}
	return func(e *env) bool {
		for _, v := range ex.fn(e) {
			if truthy(v) {
				return true
			}
		}
		return false
	}, nil
}

func truthy(v val) bool {
	switch v.k {
	case kUint, kBool, kIPv4:
		return v.u != 0
	case kInt, kTime, kRelTime:
		return v.i != 0
	case kFloat:
		return v.f != 0
	case kString:
		return v.s != ""
	case kNone:
		return true
	}
	return len(v.b) > 0
}

// pair compiles two operands, typing literals from the other side.
func (c *compiler) pair(l, r *node) (expr, expr, error) {
	var a, b expr
	var err error
	switch {
	case c.typed(l):
		if a, err = c.value(l, kNone, nil); err != nil {
			return a, b, err
		}
		b, err = c.value(r, a.k, a.field)
	case c.typed(r):
		if b, err = c.value(r, kNone, nil); err != nil {
			return a, b, err
		}
		a, err = c.value(l, b.k, b.field)
	default:
		if l.kind == nWord {
			return a, b, &Error{Msg: fmt.Sprintf("\"%s\" is not a valid protocol or protocol field.", l.val), Pos: l.pos, Len: l.end - l.pos, Unknown: l.val}
		}
		return a, b, c.errNode(l, "Constant expression is invalid on the left side of a comparison")
	}
	return a, b, err
}

func (c *compiler) compare(n *node) (testFn, error) {
	l, r := n.kids[0], n.kids[1]
	if n.op == tMatches {
		return c.matches(n)
	}
	a, b, err := c.pair(l, r)
	if err != nil {
		return nil, err
	}
	if err := c.checkOp(n, a, b); err != nil {
		return nil, err
	}
	rel := relation(n.op)
	all := n.quant == tAll
	switch n.op {
	case tNe: // all_ne
		return func(e *env) bool {
			av, bv := a.fn(e), b.fn(e)
			if len(av) == 0 || len(bv) == 0 {
				return false
			}
			for _, x := range av {
				for _, y := range bv {
					if r, ok := cmp(x, y); !ok || r == 0 {
						return false
					}
				}
			}
			return true
		}, nil
	case tAllEq:
		all = true
		rel = func(x, y val) bool { r, ok := cmp(x, y); return ok && r == 0 }
	}
	if all {
		return func(e *env) bool {
			av, bv := a.fn(e), b.fn(e)
			if len(av) == 0 || len(bv) == 0 {
				return false
			}
			for _, x := range av {
				for _, y := range bv {
					if !rel(x, y) {
						return false
					}
				}
			}
			return true
		}, nil
	}
	return func(e *env) bool {
		av := a.fn(e)
		if len(av) == 0 {
			return false
		}
		for _, y := range b.fn(e) {
			for _, x := range av {
				if rel(x, y) {
					return true
				}
			}
		}
		return false
	}, nil
}

func relation(op tokKind) func(x, y val) bool {
	switch op {
	case tEq:
		return func(x, y val) bool { r, ok := cmp(x, y); return ok && r == 0 }
	case tAnyNe:
		return func(x, y val) bool { r, ok := cmp(x, y); return ok && r != 0 }
	case tGt:
		return func(x, y val) bool { r, ok := cmp(x, y); return ok && r > 0 }
	case tGe:
		return func(x, y val) bool { r, ok := cmp(x, y); return ok && r >= 0 }
	case tLt:
		return func(x, y val) bool { r, ok := cmp(x, y); return ok && r < 0 }
	case tLe:
		return func(x, y val) bool { r, ok := cmp(x, y); return ok && r <= 0 }
	case tContains:
		return func(x, y val) bool {
			if x.k == kString && y.k == kString {
				return strings.Contains(x.s, y.s)
			}
			return bytes.Contains(x.asBytes(), y.asBytes())
		}
	case tBitAnd:
		return func(x, y val) bool {
			if x.k == kInt || y.k == kInt {
				return x.asInt()&y.asInt() != 0
			}
			return x.u&y.u != 0
		}
	}
	return func(x, y val) bool { return false }
}

func (c *compiler) checkOp(n *node, a, b expr) error {
	switch n.op {
	case tContains:
		if !a.k.bytesLike() && a.k != kNone {
			return c.errNode(n.kids[0], "%s (type=%s) cannot participate in \"contains\" comparison.", c.text(n.kids[0]), a.k)
		}
	case tBitAnd:
		if a.k != kUint && a.k != kInt && a.k != kBool {
			return c.errNode(n.kids[0], "%s (type=%s) cannot participate in a bitwise \"&\" comparison.", c.text(n.kids[0]), a.k)
		}
	case tGt, tGe, tLt, tLe:
		if a.k == kBool || a.k == kNone {
			return c.errNode(n.kids[0], "%s (type=%s) cannot participate in an ordered comparison.", c.text(n.kids[0]), a.k)
		}
	}
	if a.k == kNone && n.op != tContains {
		return c.errNode(n.kids[0], "%s is a label and cannot be compared; test its presence instead (just \"%s\")", c.text(n.kids[0]), c.text(n.kids[0]))
	}
	if _, ok := cmp(zeroOf(a.k), zeroOf(b.k)); !ok && n.op != tContains && n.op != tBitAnd {
		return c.errNode(n, "%s and %s are not of compatible types (%s vs %s).", c.text(n.kids[0]), c.text(n.kids[1]), a.k, b.k)
	}
	return nil
}

func zeroOf(k kind) val {
	v := val{k: k}
	if k == kIPv4 {
		v.bits = 32
	}
	if k == kIPv6 {
		v.bits = 128
		v.b = make([]byte, 16)
	}
	return v
}

func (c *compiler) matches(n *node) (testFn, error) {
	l, r := n.kids[0], n.kids[1]
	a, err := c.value(l, kNone, nil)
	if err != nil {
		return nil, err
	}
	if !a.k.bytesLike() {
		return nil, c.errNode(l, "%s (type=%s) cannot participate in \"matches\" comparison.", c.text(l), a.k)
	}
	if r.kind != nString {
		return nil, c.errNode(r, "The right side of \"matches\" must be a quoted regular expression")
	}
	re, err := regexp2.Compile(r.val, regexp2.IgnoreCase)
	if err != nil {
		return nil, c.errNode(r, "Invalid regular expression: %s", err.Error())
	}
	re.MatchTimeout = 200 * time.Millisecond
	return func(e *env) bool {
		for _, v := range a.fn(e) {
			if ok, _ := re.MatchString(v.asString()); ok {
				return true
			}
		}
		return false
	}, nil
}

func (c *compiler) membership(n *node) (testFn, error) {
	l, set := n.kids[0], n.kids[1]
	if !c.typed(l) {
		return nil, c.errNode(l, "\"%s\" is not a valid protocol or protocol field.", c.text(l))
	}
	a, err := c.value(l, kNone, nil)
	if err != nil {
		return nil, err
	}
	type member struct {
		lo, hi expr
		rng    bool
	}
	var members []member
	for _, el := range set.kids {
		if el.kind == nRange {
			lo, err := c.value(el.kids[0], a.k, a.field)
			if err != nil {
				return nil, err
			}
			hi, err := c.value(el.kids[1], a.k, a.field)
			if err != nil {
				return nil, err
			}
			members = append(members, member{lo, hi, true})
			continue
		}
		v, err := c.value(el, a.k, a.field)
		if err != nil {
			return nil, err
		}
		members = append(members, member{lo: v})
	}
	in := func(e *env, x val) bool {
		for _, m := range members {
			if m.rng {
				for _, lo := range m.lo.fn(e) {
					for _, hi := range m.hi.fn(e) {
						r1, ok1 := cmp(x, lo)
						r2, ok2 := cmp(x, hi)
						if ok1 && ok2 && r1 >= 0 && r2 <= 0 {
							return true
						}
					}
				}
				continue
			}
			for _, y := range m.lo.fn(e) {
				if r, ok := cmp(x, y); ok && r == 0 {
					return true
				}
			}
		}
		return false
	}
	negate := n.kind == nNotIn
	all := n.quant == tAll
	return func(e *env) bool {
		av := a.fn(e)
		if len(av) == 0 {
			return false
		}
		if negate {
			for _, x := range av {
				if in(e, x) {
					return false
				}
			}
			return true
		}
		if all {
			for _, x := range av {
				if !in(e, x) {
					return false
				}
			}
			return true
		}
		for _, x := range av {
			if in(e, x) {
				return true
			}
		}
		return false
	}, nil
}

// value compiles a value-producing node. hint is the kind of the other
// operand; literals are converted to it.
func (c *compiler) value(n *node, hint kind, hintField *dissect.FieldDef) (expr, error) {
	switch n.kind {
	case nWord:
		if f := c.lookup(n.val); f != nil && !(hint != kNone && strings.HasPrefix(n.val, ":")) {
			c.fields[f] = true
			return fieldExpr(f), nil
		}
		text := strings.TrimPrefix(n.val, ":")
		return c.lit(n, text, false, hint, hintField)
	case nString:
		return c.lit(n, n.val, true, hint, hintField)
	case nChar:
		if len(n.val) != 1 {
			return expr{}, c.errNode(n, "%s is not a valid character constant", c.text(n))
		}
		v := val{k: kUint, u: uint64(n.val[0]), i: int64(n.val[0])}
		if hint.bytesLike() {
			v = val{k: kBytes, b: []byte{n.val[0]}}
		}
		return constExpr(v), nil
	case nRef:
		f := c.lookup(n.val)
		if f == nil {
			return expr{}, c.errNode(n, "\"%s\" is not a valid protocol or protocol field.", n.val)
		}
		c.refs[f] = true
		return expr{k: kindOf(f.Type), field: f, fn: func(e *env) []val { return e.refs[f] }}, nil
	case nRaw:
		f := c.lookup(n.val)
		if f == nil {
			return expr{}, c.errNode(n, "\"%s\" is not a valid protocol or protocol field.", n.val)
		}
		c.fields[f] = true
		return expr{k: kBytes, fn: func(e *env) []val {
			var out []val
			for _, fv := range e.pi.Tree.Values(f) {
				out = append(out, val{k: kBytes, b: rawBytes(e.pi, fv)})
			}
			return out
		}}, nil
	case nSlice:
		return c.slice(n)
	case nLayer:
		child := n.kids[0]
		if child.kind != nWord {
			return expr{}, c.errNode(n, "The layer operator \"#\" can only be applied to a field")
		}
		f, err := c.field(child)
		if err != nil {
			return expr{}, err
		}
		rngs := n.rngs
		return expr{k: kindOf(f.Type), field: f, fn: func(e *env) []val {
			var out []val
			for _, fv := range e.pi.Tree.Values(f) {
				if inLayer(int(fv.Layer), rngs) {
					out = append(out, fromField(f, fv.V))
				}
			}
			return out
		}}, nil
	case nFunc:
		return c.function(n)
	case nArith:
		return c.arith(n, hint, hintField)
	case nNeg:
		child, err := c.value(n.kids[0], hint, hintField)
		if err != nil {
			return expr{}, err
		}
		if !child.k.numeric() {
			return expr{}, c.errNode(n, "Unary minus requires a number")
		}
		return expr{k: negKind(child.k), fn: func(e *env) []val {
			vs := child.fn(e)
			out := make([]val, len(vs))
			for i, v := range vs {
				out[i] = negate(v)
			}
			return out
		}}, nil
	}
	return expr{}, c.errNode(n, "\"%s\" is not a value", c.text(n))
}

func fieldExpr(f *dissect.FieldDef) expr {
	k := kindOf(f.Type)
	return expr{k: k, field: f, fn: func(e *env) []val {
		var out []val
		vals := e.pi.Tree.Vals
		for i := range vals {
			if vals[i].F == f {
				out = append(out, fromField(f, vals[i].V))
			}
		}
		return out
	}}
}

func constExpr(v val) expr {
	vs := []val{v}
	return expr{k: v.k, fn: func(*env) []val { return vs }}
}

func (c *compiler) lit(n *node, text string, quoted bool, hint kind, hintField *dissect.FieldDef) (expr, error) {
	if hint == kNone && hintField == nil {
		return constExpr(guessLiteral(text, quoted)), nil
	}
	if quoted && (hint == kUint || hint == kInt || hint == kBool) && hintField != nil && hintField.VS == nil {
		return expr{}, c.errNode(n, "\"%s\" is a string; %s is a number (remove the quotes)", text, hintField.Abbrev)
	}
	v, err := literal(hintField, hint, text, quoted)
	if err != nil {
		return expr{}, c.errNode(n, "%s", err.Error())
	}
	if hint == kString && !quoted {
		c.warn = append(c.warn, fmt.Sprintf("\"%s\" is unquoted; quote string values: \"%s\"", text, text))
	}
	return constExpr(v), nil
}

func inLayer(l int, rngs []rng) bool {
	for _, r := range rngs {
		if l >= r.start && (r.n < 0 || l < r.start+r.n) {
			return true
		}
	}
	return false
}

// rawBytes returns the packet bytes covered by a field occurrence.
func rawBytes(pi *dissect.PacketInfo, fv dissect.FieldVal) []byte {
	if int(fv.DS) >= len(pi.Sources) {
		return nil
	}
	data := pi.Sources[fv.DS].Data
	start, end := int(fv.Start), int(fv.Start)+int(fv.Len)
	if start < 0 || end > len(data) || start > end {
		return nil
	}
	return data[start:end]
}

func fieldBytes(pi *dissect.PacketInfo, f *dissect.FieldDef, fv dissect.FieldVal) ([]byte, bool) {
	switch f.Type {
	case dissect.FtString:
		return []byte(fv.V.S), true
	case dissect.FtBytes, dissect.FtProtocol, dissect.FtEther, dissect.FtIPv6, dissect.FtGUID, dissect.FtOID, dissect.FtEUI64:
		return fv.V.B, false
	}
	return rawBytes(pi, fv), false
}

func sliceBytes(b []byte, rngs []rng) []byte {
	var out []byte
	for _, r := range rngs {
		from := r.start
		if from < 0 {
			from += len(b)
		}
		to := len(b)
		if r.n >= 0 {
			to = from + r.n
		}
		if from < 0 || from > len(b) || to > len(b) || from >= to {
			return nil
		}
		out = append(out, b[from:to]...)
	}
	return out
}

func (c *compiler) slice(n *node) (expr, error) {
	child := n.kids[0]
	rngs := n.rngs
	if child.kind == nWord {
		f, err := c.field(child)
		if err != nil {
			return expr{}, err
		}
		k := kBytes
		if f.Type == dissect.FtString {
			k = kString
		}
		return expr{k: k, fn: func(e *env) []val {
			var out []val
			for _, fv := range e.pi.Tree.Values(f) {
				b, isStr := fieldBytes(e.pi, f, fv)
				s := sliceBytes(b, rngs)
				if s == nil {
					continue
				}
				if isStr {
					out = append(out, val{k: kString, s: string(s)})
				} else {
					out = append(out, val{k: kBytes, b: s})
				}
			}
			return out
		}}, nil
	}
	inner, err := c.value(child, kNone, nil)
	if err != nil {
		return expr{}, err
	}
	if !inner.k.bytesLike() {
		return expr{}, c.errNode(n, "Only byte sequences and strings can be sliced")
	}
	return expr{k: inner.k, fn: func(e *env) []val {
		var out []val
		for _, v := range inner.fn(e) {
			if s := sliceBytes(v.asBytes(), rngs); s != nil {
				if v.k == kString {
					out = append(out, val{k: kString, s: string(s)})
				} else {
					out = append(out, val{k: kBytes, b: s})
				}
			}
		}
		return out
	}}, nil
}

func negKind(k kind) kind {
	if k == kUint || k == kBool {
		return kInt
	}
	return k
}

func negate(v val) val {
	switch v.k {
	case kUint, kBool:
		return val{k: kInt, i: -int64(v.u)}
	case kFloat:
		return val{k: kFloat, f: -v.f}
	}
	v.i = -v.i
	return v
}

func (c *compiler) arith(n *node, hint kind, hintField *dissect.FieldDef) (expr, error) {
	l, r := n.kids[0], n.kids[1]
	var a, b expr
	var err error
	if c.typed(l) || !c.typed(r) {
		if a, err = c.value(l, hint, hintField); err != nil {
			return expr{}, err
		}
		if b, err = c.value(r, a.k, a.field); err != nil {
			return expr{}, err
		}
	} else {
		if b, err = c.value(r, hint, hintField); err != nil {
			return expr{}, err
		}
		if a, err = c.value(l, b.k, b.field); err != nil {
			return expr{}, err
		}
	}
	if !a.k.numeric() || !b.k.numeric() {
		return expr{}, c.errNode(n, "Arithmetic requires numbers (%s %s %s)", a.k, n.op, b.k)
	}
	k := a.k
	switch {
	case a.k == kFloat || b.k == kFloat:
		k = kFloat
	case a.k == kInt || b.k == kInt:
		k = kInt
	case a.k == kTime && (b.k == kRelTime || b.k == kUint || b.k == kInt):
		k = kTime
	}
	op := n.op
	return expr{k: k, fn: func(e *env) []val {
		var out []val
		for _, x := range a.fn(e) {
			for _, y := range b.fn(e) {
				if v, ok := arithOp(op, k, x, y); ok {
					out = append(out, v)
				}
			}
		}
		return out
	}}, nil
}

func arithOp(op tokKind, k kind, x, y val) (val, bool) {
	switch k {
	case kFloat:
		a, b := x.asFloat(), y.asFloat()
		switch op {
		case tPlus:
			return val{k: kFloat, f: a + b}, true
		case tMinus:
			return val{k: kFloat, f: a - b}, true
		case tStar:
			return val{k: kFloat, f: a * b}, true
		case tSlash:
			if b == 0 {
				return val{}, false
			}
			return val{k: kFloat, f: a / b}, true
		case tPercent:
			if b == 0 {
				return val{}, false
			}
			return val{k: kFloat, f: math.Mod(a, b)}, true
		}
	case kUint, kBool:
		a, b := x.u, y.u
		switch op {
		case tPlus:
			return val{k: kUint, u: a + b}, true
		case tMinus:
			if b > a {
				return val{k: kInt, i: int64(a) - int64(b)}, true
			}
			return val{k: kUint, u: a - b}, true
		case tStar:
			return val{k: kUint, u: a * b}, true
		case tSlash:
			if b == 0 {
				return val{}, false
			}
			return val{k: kUint, u: a / b}, true
		case tPercent:
			if b == 0 {
				return val{}, false
			}
			return val{k: kUint, u: a % b}, true
		}
	default:
		a, b := x.asInt(), y.asInt()
		var r int64
		switch op {
		case tPlus:
			r = a + b
		case tMinus:
			r = a - b
		case tStar:
			r = a * b
		case tSlash:
			if b == 0 {
				return val{}, false
			}
			r = a / b
		case tPercent:
			if b == 0 {
				return val{}, false
			}
			r = a % b
		}
		return val{k: k, i: r}, true
	}
	return val{}, false
}

var funcNames = map[string]bool{"len": true, "count": true, "upper": true, "lower": true, "string": true,
	"max": true, "min": true, "abs": true, "dec": true, "hex": true, "double": true, "float": true}

func isFuncName(s string) bool { return funcNames[strings.ToLower(s)] }

func (c *compiler) function(n *node) (expr, error) {
	name := n.val
	argc := len(n.kids)
	need := func(min, max int) error {
		if argc < min || (max >= 0 && argc > max) {
			if min == max {
				return c.errNode(n, "%s() takes %d argument(s)", name, min)
			}
			return c.errNode(n, "%s() takes at least %d argument(s)", name, min)
		}
		return nil
	}
	args := make([]expr, argc)
	for i, a := range n.kids {
		if name == "count" {
			if a.kind != nWord {
				return expr{}, c.errNode(a, "count() takes a field")
			}
		}
		ex, err := c.value(a, kNone, nil)
		if err != nil {
			return expr{}, err
		}
		args[i] = ex
	}
	switch name {
	case "len":
		if err := need(1, 1); err != nil {
			return expr{}, err
		}
		a := args[0]
		var f *dissect.FieldDef
		if n.kids[0].kind == nWord {
			f = a.field
		}
		return expr{k: kUint, fn: func(e *env) []val {
			var out []val
			if f != nil && !kindOf(f.Type).bytesLike() {
				for _, fv := range e.pi.Tree.Values(f) {
					out = append(out, val{k: kUint, u: uint64(fv.Len)})
				}
				return out
			}
			for _, v := range a.fn(e) {
				out = append(out, val{k: kUint, u: uint64(len(v.asBytes()))})
			}
			return out
		}}, nil
	case "count":
		if err := need(1, 1); err != nil {
			return expr{}, err
		}
		a := args[0]
		return expr{k: kUint, fn: func(e *env) []val {
			return []val{{k: kUint, u: uint64(len(a.fn(e)))}}
		}}, nil
	case "upper", "lower":
		if err := need(1, 1); err != nil {
			return expr{}, err
		}
		a := args[0]
		if a.k != kString {
			return expr{}, c.errNode(n, "%s() requires a string", name)
		}
		up := name == "upper"
		return expr{k: kString, fn: func(e *env) []val {
			vs := a.fn(e)
			out := make([]val, len(vs))
			for i, v := range vs {
				if up {
					out[i] = val{k: kString, s: strings.ToUpper(v.s)}
				} else {
					out[i] = val{k: kString, s: strings.ToLower(v.s)}
				}
			}
			return out
		}}, nil
	case "string", "dec", "hex":
		if err := need(1, 1); err != nil {
			return expr{}, err
		}
		a := args[0]
		return expr{k: kString, fn: func(e *env) []val {
			vs := a.fn(e)
			out := make([]val, len(vs))
			for i, v := range vs {
				s := v.asString()
				if name == "hex" && (v.k == kUint || v.k == kInt) {
					s = "0x" + strconv.FormatUint(v.u|uint64(v.i), 16)
				}
				out[i] = val{k: kString, s: s}
			}
			return out
		}}, nil
	case "double", "float":
		if err := need(1, 1); err != nil {
			return expr{}, err
		}
		a := args[0]
		return expr{k: kFloat, fn: func(e *env) []val {
			vs := a.fn(e)
			out := make([]val, len(vs))
			for i, v := range vs {
				out[i] = val{k: kFloat, f: v.asFloat()}
			}
			return out
		}}, nil
	case "abs":
		if err := need(1, 1); err != nil {
			return expr{}, err
		}
		a := args[0]
		return expr{k: a.k, fn: func(e *env) []val {
			vs := a.fn(e)
			out := make([]val, len(vs))
			for i, v := range vs {
				switch {
				case v.k == kFloat:
					v.f = math.Abs(v.f)
				case v.k == kInt && v.i < 0:
					v.i = -v.i
				}
				out[i] = v
			}
			return out
		}}, nil
	case "max", "min":
		if err := need(1, -1); err != nil {
			return expr{}, err
		}
		isMax := name == "max"
		k := args[0].k
		return expr{k: k, fn: func(e *env) []val {
			var best val
			found := false
			for _, a := range args {
				for _, v := range a.fn(e) {
					if !found {
						best, found = v, true
						continue
					}
					if r, ok := cmp(v, best); ok && ((isMax && r > 0) || (!isMax && r < 0)) {
						best = v
					}
				}
			}
			if !found {
				return nil
			}
			return []val{best}
		}}, nil
	}
	return expr{}, c.errNode(n, "Unknown function %s()", name)
}
