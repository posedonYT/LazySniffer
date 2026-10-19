package dissect

import (
	"fmt"
	"strings"
)

// NodeFlags mark special tree items.
type NodeFlags uint8

const (
	NodeGenerated NodeFlags = 1 << iota // value computed by the dissector, shown in [brackets]
	NodeHidden                          // filterable but not displayed
	NodeExpert                          // carries expert info
)

// Node is an item of the protocol tree.
type Node struct {
	Field  *FieldDef
	Value  Value
	raw    uint64 // raw containing integer for bitmask display
	label  string // custom label; empty means derived from Field/Value
	DS     uint8
	Start  int32
	Length int32
	Flags  NodeFlags
	Expert *ExpertInfo
	// Link is a related frame number (request/response), 0 if none.
	Link uint32

	Parent      *Node
	First, Last *Node
	Next        *Node
	tree        *Tree
}

// FieldVal is one occurrence of a field in a dissected packet, used by the
// display filter engine and columns.
type FieldVal struct {
	F     *FieldDef
	V     Value
	Layer uint8
	DS    uint8
	Start int32
	Len   int32
	Node  *Node // nil when the tree was not built
}

// Tree collects fields of one packet. In full mode it builds displayable
// nodes; in fields mode it only records values of wanted fields.
type Tree struct {
	PI   *PacketInfo
	full bool
	want []bool // indexed by FieldID; nil means want everything
	Root Node
	Vals []FieldVal
	sink Node

	slab   []Node
	layers []uint8 // per-protocol occurrence counter
}

// NewTree creates a tree. full builds displayable nodes. want (indexed by
// FieldID) limits which values are recorded; nil records all.
func NewTree(full bool, want []bool) *Tree {
	t := &Tree{full: full, want: want}
	t.Root.tree = t
	t.sink.tree = t
	return t
}

// Reset clears the tree for reuse.
func (t *Tree) Reset() {
	t.Root = Node{tree: t}
	t.Vals = t.Vals[:0]
	t.slab = nil
	for i := range t.layers {
		t.layers[i] = 0
	}
}

// Full reports whether the tree builds displayable nodes.
func (t *Tree) Full() bool { return t.full }

// Wants reports whether values of f are recorded.
func (t *Tree) Wants(f *FieldDef) bool {
	return t.want == nil || (int(f.ID) < len(t.want) && t.want[f.ID])
}

func (t *Tree) newNode() *Node {
	if len(t.slab) == 0 {
		t.slab = make([]Node, 64)
	}
	n := &t.slab[0]
	t.slab = t.slab[1:]
	return n
}

func (t *Tree) layerOf(p *Proto) uint8 {
	if p == nil {
		return 1
	}
	for len(t.layers) <= p.Index {
		t.layers = append(t.layers, 0)
	}
	if t.layers[p.Index] == 0 {
		return 1
	}
	return t.layers[p.Index]
}

// Values returns all recorded occurrences of f.
func (t *Tree) Values(f *FieldDef) []FieldVal {
	var out []FieldVal
	for i := range t.Vals {
		if t.Vals[i].F == f {
			out = append(out, t.Vals[i])
		}
	}
	return out
}

// First returns the first occurrence of f.
func (t *Tree) First(f *FieldDef) (FieldVal, bool) {
	for i := range t.Vals {
		if t.Vals[i].F == f {
			return t.Vals[i], true
		}
	}
	return FieldVal{}, false
}

func (n *Node) add(f *FieldDef, tvb *Tvb, off, length int, v Value, flags NodeFlags) *Node {
	t := n.tree
	layer := uint8(1)
	if f != nil {
		if f.Type == FtProtocol {
			for len(t.layers) <= f.Proto.Index {
				t.layers = append(t.layers, 0)
			}
			t.layers[f.Proto.Index]++
			if t.PI != nil && f.Proto.Filter[0] != '_' && f.Proto.Filter != "frame" {
				t.PI.Protocols = append(t.PI.Protocols, f.Proto.Filter)
			}
		}
		layer = t.layerOf(f.Proto)
	}
	c := &t.sink
	if t.full && n != &t.sink {
		c = t.newNode()
		*c = Node{Field: f, Value: v, Flags: flags, Parent: n, tree: t}
		if tvb != nil {
			c.DS, c.Start, c.Length = tvb.ds, int32(tvb.base+off), int32(length)
		}
		if n.Last == nil {
			n.First, n.Last = c, c
		} else {
			n.Last.Next = c
			n.Last = c
		}
	}
	if f != nil && t.Wants(f) {
		fv := FieldVal{F: f, V: v, Layer: layer}
		if tvb != nil {
			fv.DS, fv.Start, fv.Len = tvb.ds, int32(tvb.base+off), int32(length)
		}
		if c != &t.sink {
			fv.Node = c
		}
		t.Vals = append(t.Vals, fv)
	}
	return c
}

// Tree returns the tree the node belongs to.
func (n *Node) Tree() *Tree { return n.tree }

// IsSink reports whether this is the placeholder node of a fields-mode tree.
func (n *Node) IsSink() bool { return n == &n.tree.sink }

// AddProtocol adds a protocol item covering length bytes (-1: to the end).
func (n *Node) AddProtocol(p *Proto, tvb *Tvb, off, length int) *Node {
	if length < 0 {
		length = tvb.Remaining(off)
	}
	var b []byte
	if tvb != nil && tvb.Has(off, length) {
		b = tvb.data[off : off+length]
	}
	return n.add(p.HF, tvb, off, length, Value{T: FtProtocol, B: b}, 0)
}

// AddUint adds an unsigned field read big-endian from size bytes at off.
func (n *Node) AddUint(f *FieldDef, tvb *Tvb, off, size int) (*Node, uint64) {
	raw := tvb.UintN(off, size, false)
	v := f.Masked(raw)
	c := n.add(f, tvb, off, size, Value{T: f.Type, U: v}, 0)
	c.raw = raw
	return c, v
}

// AddUintLE is AddUint for little-endian values.
func (n *Node) AddUintLE(f *FieldDef, tvb *Tvb, off, size int) (*Node, uint64) {
	raw := tvb.UintN(off, size, true)
	v := f.Masked(raw)
	c := n.add(f, tvb, off, size, Value{T: f.Type, U: v}, 0)
	c.raw = raw
	return c, v
}

// AddUintValue adds an integer field with an explicit value.
func (n *Node) AddUintValue(f *FieldDef, tvb *Tvb, off, size int, v uint64) *Node {
	c := n.add(f, tvb, off, size, Value{T: f.Type, U: v}, 0)
	c.raw = v << f.shift
	return c
}

// AddBits adds a bitmask field whose containing integer was already read.
func (n *Node) AddBits(f *FieldDef, tvb *Tvb, off, size int, raw uint64) *Node {
	c := n.add(f, tvb, off, size, Value{T: f.Type, U: f.Masked(raw)}, 0)
	c.raw = raw
	return c
}

// AddBool adds a boolean (bitmask) field from an already-read integer.
func (n *Node) AddBool(f *FieldDef, tvb *Tvb, off, size int, raw uint64) *Node {
	return n.AddBits(f, tvb, off, size, raw)
}

// AddBytes adds a bytes-like field (bytes, MAC, IPv6, GUID).
func (n *Node) AddBytes(f *FieldDef, tvb *Tvb, off, length int) (*Node, []byte) {
	if length < 0 {
		length = tvb.Remaining(off)
	}
	b := tvb.Bytes(off, length)
	return n.add(f, tvb, off, length, Value{T: f.Type, B: b}, 0), b
}

// AddIPv4 adds an IPv4 address field.
func (n *Node) AddIPv4(f *FieldDef, tvb *Tvb, off int) (*Node, uint32) {
	a := tvb.U32(off)
	return n.add(f, tvb, off, 4, Value{T: FtIPv4, U: uint64(a)}, 0), a
}

// AddString adds a string field of length bytes at off.
func (n *Node) AddString(f *FieldDef, tvb *Tvb, off, length int) (*Node, string) {
	if length < 0 {
		length = tvb.Remaining(off)
	}
	s := tvb.String(off, length)
	return n.add(f, tvb, off, length, Value{T: FtString, S: s}, 0), s
}

// AddValue adds a field with an explicit value covering bytes of tvb.
func (n *Node) AddValue(f *FieldDef, tvb *Tvb, off, length int, v Value) *Node {
	v.T = f.Type
	return n.add(f, tvb, off, length, v, 0)
}

// AddGenerated adds a generated field ([value] in brackets) not backed by bytes.
func (n *Node) AddGenerated(f *FieldDef, v Value) *Node {
	v.T = f.Type
	c := n.add(f, nil, 0, 0, v, NodeGenerated)
	if c != &n.tree.sink {
		c.DS, c.Start, c.Length = n.DS, n.Start, 0
	}
	return c
}

// AddHidden adds a field that is filterable but not shown (like ip.addr).
func (n *Node) AddHidden(f *FieldDef, tvb *Tvb, off, length int, v Value) *Node {
	v.T = f.Type
	return n.add(f, tvb, off, length, v, NodeHidden)
}

// AddText adds a text-only item.
func (n *Node) AddText(tvb *Tvb, off, length int, format string, args ...any) *Node {
	if !n.tree.full {
		return &n.tree.sink
	}
	c := n.add(nil, tvb, off, length, Value{}, 0)
	c.label = fmt.Sprintf(format, args...)
	return c
}

// SetText replaces the node label.
func (n *Node) SetText(format string, args ...any) *Node {
	if n.tree.full && n != &n.tree.sink {
		if len(args) == 0 {
			n.label = format
		} else {
			n.label = fmt.Sprintf(format, args...)
		}
	}
	return n
}

// AppendText appends to the node label.
func (n *Node) AppendText(format string, args ...any) *Node {
	if n.tree.full && n != &n.tree.sink {
		if n.label == "" {
			n.label = n.defaultLabel()
		}
		n.label += fmt.Sprintf(format, args...)
	}
	return n
}

// SetLen updates the byte length covered by the node.
func (n *Node) SetLen(length int) *Node {
	if n != &n.tree.sink {
		n.Length = int32(length)
	}
	for i := len(n.tree.Vals) - 1; i >= 0; i-- {
		if n.tree.Vals[i].Node == n && n.tree.full {
			n.tree.Vals[i].Len = int32(length)
			break
		}
	}
	return n
}

// SetGenerated marks the node as generated.
func (n *Node) SetGenerated() *Node {
	if n != &n.tree.sink {
		n.Flags |= NodeGenerated
	}
	return n
}

// SetHidden hides the node from display.
func (n *Node) SetHidden() *Node {
	if n != &n.tree.sink {
		n.Flags |= NodeHidden
	}
	return n
}

// SetLink attaches a related frame number (e.g. [Response in: 7]).
func (n *Node) SetLink(frame uint32) *Node {
	if n != &n.tree.sink {
		n.Link = frame
	}
	return n
}

// Children iterates over child nodes.
func (n *Node) Children() []*Node {
	var out []*Node
	for c := n.First; c != nil; c = c.Next {
		out = append(out, c)
	}
	return out
}

// HasChildren reports whether the node has visible children.
func (n *Node) HasChildren() bool {
	for c := n.First; c != nil; c = c.Next {
		if c.Flags&NodeHidden == 0 {
			return true
		}
	}
	return false
}

// Text is the display label of the node.
func (n *Node) Text() string {
	s := n.label
	if s == "" {
		s = n.defaultLabel()
	}
	if n.Flags&NodeGenerated != 0 && !strings.HasPrefix(s, "[") {
		s = "[" + s + "]"
	}
	return s
}

func (n *Node) defaultLabel() string {
	f := n.Field
	if f == nil {
		return ""
	}
	switch f.Type {
	case FtNone:
		return f.Name
	case FtProtocol:
		return f.Name
	}
	val := f.Display(n.Value)
	if f.Bitmask != 0 {
		return f.BitPattern(n.raw) + " = " + f.Name + ": " + val
	}
	return f.Name + ": " + val
}

// Path returns the chain of labels from the root (for copy/expand state).
func (n *Node) Path() string {
	var parts []string
	for c := n; c != nil && c.Parent != nil; c = c.Parent {
		key := c.label
		if c.Field != nil {
			key = c.Field.Abbrev
		}
		parts = append(parts, key)
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, "/")
}

// Walk calls fn for n and all descendants in display order. Returning false
// from fn skips the node's children.
func (n *Node) Walk(fn func(*Node, int) bool) {
	var rec func(*Node, int)
	rec = func(x *Node, depth int) {
		for c := x.First; c != nil; c = c.Next {
			if fn(c, depth) {
				rec(c, depth+1)
			}
		}
	}
	rec(n, 0)
}
