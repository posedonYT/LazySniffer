// Package lua loads Lua dissector plugins that use a subset of Wireshark's
// Lua API: Proto, ProtoField, DissectorTable, Tvb/TvbRange, TreeItem and
// Pinfo columns.
package lua

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	glua "github.com/yuin/gopher-lua"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

// Plugin is a loaded .lua file.
type Plugin struct {
	Path   string
	Protos []string
}

var (
	mu      sync.Mutex // Lua states are not goroutine safe; dissection is serialized
	loaded  []Plugin
	handles = map[string]*luaProto{}
)

type pendingField struct {
	abbr, name string
	ft         d.FieldType
	base       d.Base
	mask       uint64
	vs         map[uint64]string
	def        *d.FieldDef
}

type luaProto struct {
	name, desc string
	proto      *d.Proto
	fields     []*pendingField
	L          *glua.LState
	dissector  *glua.LFunction
	handle     *d.Handle
}

// Loaded lists the plugins loaded so far.
func Loaded() []Plugin { return loaded }

// LoadDir loads every *.lua file of dir, returning one error per failing file.
func LoadDir(dir string) []error {
	files, _ := filepath.Glob(filepath.Join(dir, "*.lua"))
	sort.Strings(files)
	var errs []error
	for _, f := range files {
		if err := LoadFile(f); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(f), err))
		}
	}
	return errs
}

// LoadFile runs a plugin script.
func LoadFile(path string) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return load(path, string(src))
}

// LoadString runs plugin source (tests).
func LoadString(name, src string) error { return load(name, src) }

func load(path, src string) error {
	mu.Lock()
	defer mu.Unlock()
	L := glua.NewState()
	var protos []*luaProto
	install(L, &protos)
	if err := L.DoString(src); err != nil {
		L.Close()
		return err
	}
	pl := Plugin{Path: path}
	for _, p := range protos {
		p.L = L
		pl.Protos = append(pl.Protos, p.name)
	}
	loaded = append(loaded, pl)
	return nil
}

// ---- type metatables ----

const (
	tProto = "Proto"
	tField = "ProtoField"
	tTvb   = "Tvb"
	tRange = "TvbRange"
	tTree  = "TreeItem"
	tPinfo = "Pinfo"
	tCols  = "Columns"
	tCol   = "Column"
	tTable = "DissectorTable"
)

type tvbRange struct {
	tvb      *d.Tvb
	off, len int
}

type treeItem struct {
	node *d.Node
	pi   *d.PacketInfo
}

type column struct {
	pi   *d.PacketInfo
	info bool
}

func install(L *glua.LState, protos *[]*luaProto) {
	// base.*
	base := L.NewTable()
	for name, v := range map[string]int{"NONE": 0, "DEC": 1, "HEX": 2, "OCT": 3, "DEC_HEX": 4, "HEX_DEC": 5} {
		base.RawSetString(name, glua.LNumber(v))
	}
	L.SetGlobal("base", base)
	L.SetGlobal("ftypes", L.NewTable())

	// Proto(name, description)
	protoMT := L.NewTypeMetatable(tProto)
	L.SetGlobal("Proto", L.NewFunction(func(L *glua.LState) int {
		name, desc := L.CheckString(1), L.OptString(2, "")
		if desc == "" {
			desc = name
		}
		p := &luaProto{name: name, desc: desc, proto: d.RegisterProto(desc, strings.ToUpper(name), strings.ToLower(name))}
		p.handle = d.RegisterHandle("lua:"+name, d.NewHandle(p.proto, p.dissect))
		*protos = append(*protos, p)
		handles[name] = p
		ud := L.NewUserData()
		ud.Value = p
		L.SetMetatable(ud, protoMT)
		L.Push(ud)
		return 1
	}))
	L.SetField(protoMT, "__index", L.NewFunction(func(L *glua.LState) int {
		p := checkProto(L, 1)
		switch L.CheckString(2) {
		case "name":
			L.Push(glua.LString(p.name))
		case "description":
			L.Push(glua.LString(p.desc))
		case "dissector":
			if p.dissector != nil {
				L.Push(p.dissector)
			} else {
				L.Push(glua.LNil)
			}
		default:
			L.Push(glua.LNil)
		}
		return 1
	}))
	L.SetField(protoMT, "__newindex", L.NewFunction(func(L *glua.LState) int {
		p := checkProto(L, 1)
		switch L.CheckString(2) {
		case "dissector":
			p.dissector = L.CheckFunction(3)
		case "fields":
			tbl := L.CheckTable(3)
			tbl.ForEach(func(_, v glua.LValue) {
				if ud, ok := v.(*glua.LUserData); ok {
					if f, ok := ud.Value.(*pendingField); ok {
						p.register(f)
					}
				}
			})
		}
		return 0
	}))

	// ProtoField constructors
	fieldMT := L.NewTypeMetatable(tField)
	_ = fieldMT
	pf := L.NewTable()
	add := func(name string, ft d.FieldType) {
		L.SetField(pf, name, L.NewFunction(func(L *glua.LState) int {
			f := &pendingField{abbr: L.CheckString(1), name: L.OptString(2, ""), ft: ft}
			if f.name == "" {
				f.name = f.abbr
			}
			if b := L.Get(3); b != glua.LNil {
				if n, ok := b.(glua.LNumber); ok {
					f.base = map[int]d.Base{0: d.BaseNone, 1: d.BaseDec, 2: d.BaseHex, 4: d.BaseDecHex, 5: d.BaseHexDec}[int(n)]
				}
			}
			if t, ok := L.Get(4).(*glua.LTable); ok {
				f.vs = map[uint64]string{}
				t.ForEach(func(k, v glua.LValue) {
					if kn, ok := k.(glua.LNumber); ok {
						f.vs[uint64(kn)] = v.String()
					}
				})
			}
			if m, ok := L.Get(5).(glua.LNumber); ok {
				f.mask = uint64(m)
			}
			ud := L.NewUserData()
			ud.Value = f
			L.SetMetatable(ud, L.GetTypeMetatable(tField))
			L.Push(ud)
			return 1
		}))
	}
	for name, ft := range map[string]d.FieldType{"uint8": d.FtUint8, "uint16": d.FtUint16, "uint24": d.FtUint24, "uint32": d.FtUint32, "uint64": d.FtUint64,
		"int8": d.FtInt8, "int16": d.FtInt16, "int24": d.FtInt24, "int32": d.FtInt32, "int64": d.FtInt64, "string": d.FtString, "stringz": d.FtString,
		"bytes": d.FtBytes, "bool": d.FtBool, "ipv4": d.FtIPv4, "ipv6": d.FtIPv6, "ether": d.FtEther, "float": d.FtFloat, "double": d.FtDouble, "framenum": d.FtFrameNum} {
		add(name, ft)
	}
	L.SetGlobal("ProtoField", pf)

	// DissectorTable.get(name):add(key, proto)
	tblMT := L.NewTypeMetatable(tTable)
	L.SetField(tblMT, "__index", L.NewFunction(func(L *glua.LState) int {
		switch L.CheckString(2) {
		case "add":
			L.Push(L.NewFunction(func(L *glua.LState) int {
				t := L.CheckUserData(1).Value.(*d.UintTable)
				p := checkProto(L, 3)
				key := uint64(L.CheckNumber(2))
				t.Add(key, p.handle)
				return 0
			}))
		default:
			L.Push(glua.LNil)
		}
		return 1
	}))
	dt := L.NewTable()
	L.SetField(dt, "get", L.NewFunction(func(L *glua.LState) int {
		ud := L.NewUserData()
		ud.Value = d.Table(L.CheckString(1))
		L.SetMetatable(ud, tblMT)
		L.Push(ud)
		return 1
	}))
	L.SetGlobal("DissectorTable", dt)
	installTvb(L)
}

func checkProto(L *glua.LState, n int) *luaProto {
	ud := L.CheckUserData(n)
	p, ok := ud.Value.(*luaProto)
	if !ok {
		L.ArgError(n, "Proto expected")
	}
	return p
}

func (p *luaProto) register(f *pendingField) {
	opts := []d.FieldOpt{}
	if f.base != d.BaseNone {
		opts = append(opts, d.WithBase(f.base))
	}
	if f.mask != 0 {
		opts = append(opts, d.WithMask(f.mask))
	}
	if f.vs != nil {
		opts = append(opts, d.WithVS(f.vs))
	}
	f.def = p.proto.Field(f.abbr, f.name, f.ft, opts...)
	p.fields = append(p.fields, f)
}

// dissect is the native entry point of a Lua dissector.
func (p *luaProto) dissect(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if p.dissector == nil {
		return 0
	}
	mu.Lock()
	defer mu.Unlock()
	L := p.L
	tvbUD := L.NewUserData()
	tvbUD.Value = &tvbRange{tvb: tvb, off: 0, len: tvb.Len()}
	L.SetMetatable(tvbUD, L.GetTypeMetatable(tTvb))
	pinfoUD := L.NewUserData()
	pinfoUD.Value = pi
	L.SetMetatable(pinfoUD, L.GetTypeMetatable(tPinfo))
	treeUD := L.NewUserData()
	treeUD.Value = &treeItem{node: tree, pi: pi}
	L.SetMetatable(treeUD, L.GetTypeMetatable(tTree))
	if err := L.CallByParam(glua.P{Fn: p.dissector, NRet: 1, Protect: true}, tvbUD, pinfoUD, treeUD); err != nil {
		panic(fmt.Sprintf("Lua plugin %s: %v", p.name, err)) // shown as a dissector bug on the frame
	}
	ret := L.Get(-1)
	L.Pop(1)
	if n, ok := ret.(glua.LNumber); ok && n > 0 {
		return int(n)
	}
	return tvb.Len()
}

func installTvb(L *glua.LState) {
	mt := L.NewTypeMetatable(tTvb)
	L.SetField(mt, "__call", L.NewFunction(rangeCall))
	L.SetField(mt, "__index", L.NewFunction(tvbIndex))
	L.SetField(mt, "__len", L.NewFunction(func(L *glua.LState) int {
		L.Push(glua.LNumber(L.CheckUserData(1).Value.(*tvbRange).len))
		return 1
	}))
	rmt := L.NewTypeMetatable(tRange)
	L.SetField(rmt, "__index", L.NewFunction(tvbIndex))
	L.SetField(rmt, "__call", L.NewFunction(rangeCall))

	// TreeItem
	tmt := L.NewTypeMetatable(tTree)
	L.SetField(tmt, "__index", L.NewFunction(func(L *glua.LState) int {
		switch L.CheckString(2) {
		case "add", "add_le":
			le := L.CheckString(2) == "add_le"
			L.Push(L.NewFunction(func(L *glua.LState) int { return treeAdd(L, le) }))
		case "set_text":
			L.Push(L.NewFunction(func(L *glua.LState) int {
				it := L.CheckUserData(1).Value.(*treeItem)
				it.node.SetText("%s", L.CheckString(2))
				L.Push(L.Get(1))
				return 1
			}))
		case "append_text":
			L.Push(L.NewFunction(func(L *glua.LState) int {
				it := L.CheckUserData(1).Value.(*treeItem)
				it.node.AppendText("%s", L.CheckString(2))
				L.Push(L.Get(1))
				return 1
			}))
		case "set_len":
			L.Push(L.NewFunction(func(L *glua.LState) int {
				it := L.CheckUserData(1).Value.(*treeItem)
				it.node.SetLen(int(L.CheckNumber(2)))
				return 0
			}))
		case "add_expert_info", "set_generated", "set_hidden":
			L.Push(L.NewFunction(func(L *glua.LState) int { return 0 }))
		default:
			L.Push(glua.LNil)
		}
		return 1
	}))

	// Pinfo with cols
	pmt := L.NewTypeMetatable(tPinfo)
	cmt := L.NewTypeMetatable(tCols)
	colmt := L.NewTypeMetatable(tCol)
	L.SetField(pmt, "__index", L.NewFunction(func(L *glua.LState) int {
		pi := L.CheckUserData(1).Value.(*d.PacketInfo)
		switch L.CheckString(2) {
		case "cols":
			ud := L.NewUserData()
			ud.Value = pi
			L.SetMetatable(ud, cmt)
			L.Push(ud)
		case "number":
			L.Push(glua.LNumber(pi.Num))
		case "len":
			L.Push(glua.LNumber(pi.Len))
		case "src":
			L.Push(glua.LString(pi.Src.String()))
		case "dst":
			L.Push(glua.LString(pi.Dst.String()))
		case "src_port":
			L.Push(glua.LNumber(pi.SrcPort))
		case "dst_port":
			L.Push(glua.LNumber(pi.DstPort))
		case "abs_ts":
			L.Push(glua.LNumber(float64(pi.TS) / 1e9))
		default:
			L.Push(glua.LNil)
		}
		return 1
	}))
	L.SetField(cmt, "__index", L.NewFunction(func(L *glua.LState) int {
		pi := L.CheckUserData(1).Value.(*d.PacketInfo)
		ud := L.NewUserData()
		ud.Value = &column{pi: pi, info: L.CheckString(2) == "info"}
		L.SetMetatable(ud, colmt)
		L.Push(ud)
		return 1
	}))
	L.SetField(cmt, "__newindex", L.NewFunction(func(L *glua.LState) int {
		pi := L.CheckUserData(1).Value.(*d.PacketInfo)
		switch L.CheckString(2) {
		case "protocol":
			pi.SetProtocol(L.CheckString(3))
		case "info":
			pi.SetInfo(L.CheckString(3))
		}
		return 0
	}))
	L.SetField(colmt, "__index", L.NewFunction(func(L *glua.LState) int {
		switch L.CheckString(2) {
		case "set":
			L.Push(L.NewFunction(func(L *glua.LState) int {
				c := L.CheckUserData(1).Value.(*column)
				if c.info {
					c.pi.SetInfo(L.CheckString(2))
				} else {
					c.pi.SetProtocol(L.CheckString(2))
				}
				return 0
			}))
		case "append":
			L.Push(L.NewFunction(func(L *glua.LState) int {
				c := L.CheckUserData(1).Value.(*column)
				if c.info {
					c.pi.AppendInfo("%s", L.CheckString(2))
				}
				return 0
			}))
		case "clear":
			L.Push(L.NewFunction(func(L *glua.LState) int {
				c := L.CheckUserData(1).Value.(*column)
				if c.info {
					c.pi.ClearInfo()
				}
				return 0
			}))
		default:
			L.Push(glua.LNil)
		}
		return 1
	}))
}

func newRange(L *glua.LState, tvb *d.Tvb, off, n int) *glua.LUserData {
	ud := L.NewUserData()
	ud.Value = &tvbRange{tvb: tvb, off: off, len: n}
	L.SetMetatable(ud, L.GetTypeMetatable(tRange))
	return ud
}

// rangeCall implements buffer(offset, length).
func rangeCall(L *glua.LState) int {
	r := L.CheckUserData(1).Value.(*tvbRange)
	off := int(L.OptNumber(2, 0))
	n := int(L.OptNumber(3, glua.LNumber(r.len-off)))
	if off < 0 || n < 0 || off+n > r.len {
		L.ArgError(2, "out of bounds")
	}
	L.Push(newRange(L, r.tvb, r.off+off, n))
	return 1
}

func tvbIndex(L *glua.LState) int {
	r := L.CheckUserData(1).Value.(*tvbRange)
	name := L.CheckString(2)
	get := func(le bool, signed bool) glua.LValue {
		n := min(r.len, 8)
		if n == 0 {
			return glua.LNumber(0)
		}
		v := r.tvb.UintN(r.off, n, le)
		if signed {
			shift := uint(64 - 8*n)
			return glua.LNumber(float64(int64(v<<shift) >> shift))
		}
		return glua.LNumber(float64(v))
	}
	fn := func(f func(L *glua.LState) glua.LValue) {
		L.Push(L.NewFunction(func(L *glua.LState) int { L.Push(f(L)); return 1 }))
	}
	switch name {
	case "len":
		fn(func(L *glua.LState) glua.LValue { return glua.LNumber(r.len) })
	case "offset":
		fn(func(L *glua.LState) glua.LValue { return glua.LNumber(r.off) })
	case "range":
		L.Push(L.NewFunction(rangeCall))
	case "uint", "uint64":
		fn(func(L *glua.LState) glua.LValue { return get(false, false) })
	case "le_uint", "le_uint64":
		fn(func(L *glua.LState) glua.LValue { return get(true, false) })
	case "int", "int64":
		fn(func(L *glua.LState) glua.LValue { return get(false, true) })
	case "le_int", "le_int64":
		fn(func(L *glua.LState) glua.LValue { return get(true, true) })
	case "string", "stringz":
		fn(func(L *glua.LState) glua.LValue { return glua.LString(r.tvb.String(r.off, r.len)) })
	case "bytes", "raw":
		fn(func(L *glua.LState) glua.LValue { return glua.LString(string(r.tvb.Bytes(r.off, r.len))) })
	case "float":
		fn(func(L *glua.LState) glua.LValue {
			return glua.LNumber(math.Float32frombits(uint32(r.tvb.UintN(r.off, 4, false))))
		})
	case "ipv4":
		fn(func(L *glua.LState) glua.LValue {
			b := r.tvb.Bytes(r.off, 4)
			return glua.LString(fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]))
		})
	case "tvb":
		fn(func(L *glua.LState) glua.LValue { return L.Get(1) })
	default:
		L.Push(glua.LNil)
	}
	return 1
}

// treeAdd implements tree:add(protoOrField, range [, value] [, text…]).
func treeAdd(L *glua.LState, le bool) int {
	it := L.CheckUserData(1).Value.(*treeItem)
	target := L.CheckUserData(2).Value
	var r *tvbRange
	next := 3
	if ud, ok := L.Get(3).(*glua.LUserData); ok {
		if rr, ok := ud.Value.(*tvbRange); ok {
			r = rr
			next = 4
		}
	}
	out := L.NewUserData()
	L.SetMetatable(out, L.GetTypeMetatable(tTree))
	switch t := target.(type) {
	case *luaProto:
		off, n := 0, 0
		var tvb *d.Tvb
		if r != nil {
			tvb, off, n = r.tvb, r.off, r.len
		}
		node := it.node.AddProtocol(t.proto, tvb, off, n)
		if L.GetTop() >= next {
			node.SetText("%s", L.ToString(next))
		}
		out.Value = &treeItem{node: node, pi: it.pi}
	case *pendingField:
		f := t.def
		if f == nil {
			L.RaiseError("field %s is not registered (assign it to proto.fields)", t.abbr)
		}
		var node *d.Node
		explicit := L.GetTop() >= next && L.Get(next) != glua.LNil
		switch {
		case r == nil:
			node = it.node.AddValue(f, nil, 0, 0, luaValue(f, L.Get(next)))
		case explicit:
			node = it.node.AddValue(f, r.tvb, r.off, r.len, luaValue(f, L.Get(next)))
			next++
		default:
			node = addFromRange(it.node, f, r, le)
		}
		if L.GetTop() >= next {
			if s := L.ToString(next); s != "" && node != nil {
				node.AppendText(": %s", s)
			}
		}
		out.Value = &treeItem{node: node, pi: it.pi}
	default:
		L.ArgError(2, "Proto or ProtoField expected")
	}
	L.Push(out)
	return 1
}

func luaValue(f *d.FieldDef, v glua.LValue) d.Value {
	switch f.Type {
	case d.FtString:
		return d.StringValue(v.String())
	case d.FtBytes:
		return d.BytesValue(d.FtBytes, []byte(v.String()))
	case d.FtFloat, d.FtDouble:
		if n, ok := v.(glua.LNumber); ok {
			return d.FloatValue(f.Type, float64(n))
		}
	}
	if n, ok := v.(glua.LNumber); ok {
		return d.UintValue(f.Type, uint64(int64(n)))
	}
	if b, ok := v.(glua.LBool); ok {
		return d.BoolValue(bool(b))
	}
	return d.Value{T: f.Type}
}

func addFromRange(n *d.Node, f *d.FieldDef, r *tvbRange, le bool) *d.Node {
	switch f.Type {
	case d.FtString:
		node, _ := n.AddString(f, r.tvb, r.off, r.len)
		return node
	case d.FtBytes, d.FtEther, d.FtIPv6:
		node, _ := n.AddBytes(f, r.tvb, r.off, r.len)
		return node
	case d.FtIPv4:
		node, _ := n.AddIPv4(f, r.tvb, r.off)
		return node
	case d.FtBool:
		node := n.AddBits(f, r.tvb, r.off, r.len, r.tvb.UintN(r.off, r.len, le))
		return node
	case d.FtFloat, d.FtDouble:
		v := math.Float32frombits(uint32(r.tvb.UintN(r.off, 4, le)))
		return n.AddValue(f, r.tvb, r.off, r.len, d.FloatValue(f.Type, float64(v)))
	}
	if f.Bitmask != 0 {
		return n.AddBits(f, r.tvb, r.off, r.len, r.tvb.UintN(r.off, r.len, le))
	}
	if f.Type.IsSigned() {
		v := r.tvb.UintN(r.off, r.len, le)
		shift := uint(64 - 8*r.len)
		return n.AddValue(f, r.tvb, r.off, r.len, d.IntValue(f.Type, int64(v<<shift)>>shift))
	}
	if le {
		node, _ := n.AddUintLE(f, r.tvb, r.off, r.len)
		return node
	}
	node, _ := n.AddUint(f, r.tvb, r.off, r.len)
	return node
}
