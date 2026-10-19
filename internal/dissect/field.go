// Package dissect is the native dissection engine: field registry, packet
// buffers, protocol trees, dissector tables and capture-wide state.
//
// Field abbreviations follow Wireshark so display filters, columns and
// coloring rules are portable between the two tools.
package dissect

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// FieldType is the type of a field's value (Wireshark's ftenum).
type FieldType uint8

const (
	FtNone FieldType = iota
	FtProtocol
	FtBool
	FtChar
	FtUint8
	FtUint16
	FtUint24
	FtUint32
	FtUint40
	FtUint48
	FtUint56
	FtUint64
	FtInt8
	FtInt16
	FtInt24
	FtInt32
	FtInt64
	FtFloat
	FtDouble
	FtAbsTime
	FtRelTime
	FtString
	FtBytes
	FtEther
	FtIPv4
	FtIPv6
	FtFrameNum
	FtGUID
	FtOID
	FtEUI64
)

var ftNames = [...]string{
	FtNone: "Label", FtProtocol: "Protocol", FtBool: "Boolean", FtChar: "Character (8 bits)",
	FtUint8: "Unsigned integer (8 bits)", FtUint16: "Unsigned integer (16 bits)",
	FtUint24: "Unsigned integer (24 bits)", FtUint32: "Unsigned integer (32 bits)",
	FtUint40: "Unsigned integer (40 bits)", FtUint48: "Unsigned integer (48 bits)",
	FtUint56: "Unsigned integer (56 bits)", FtUint64: "Unsigned integer (64 bits)",
	FtInt8: "Signed integer (8 bits)", FtInt16: "Signed integer (16 bits)",
	FtInt24: "Signed integer (24 bits)", FtInt32: "Signed integer (32 bits)",
	FtInt64: "Signed integer (64 bits)", FtFloat: "Single-precision floating point",
	FtDouble: "Double-precision floating point", FtAbsTime: "Date and time",
	FtRelTime: "Time offset", FtString: "Character string", FtBytes: "Byte sequence",
	FtEther: "Ethernet or other MAC address", FtIPv4: "IPv4 address", FtIPv6: "IPv6 address",
	FtFrameNum: "Frame number", FtGUID: "Globally Unique Identifier", FtOID: "ASN.1 object identifier",
	FtEUI64: "EUI64 address",
}

func (t FieldType) String() string {
	if int(t) < len(ftNames) {
		return ftNames[t]
	}
	return "unknown"
}

// IsUnsigned reports whether values are stored in Value.U as unsigned ints.
func (t FieldType) IsUnsigned() bool {
	return (t >= FtUint8 && t <= FtUint64) || t == FtChar || t == FtFrameNum
}

// IsSigned reports whether values are signed integers (stored as int64 bits in U).
func (t FieldType) IsSigned() bool { return t >= FtInt8 && t <= FtInt64 }

// IsInteger reports whether the type is any integer kind (including bool).
func (t FieldType) IsInteger() bool { return t.IsUnsigned() || t.IsSigned() || t == FtBool }

// Bits is the width of an integer type.
func (t FieldType) Bits() int {
	switch t {
	case FtBool, FtUint8, FtInt8, FtChar:
		return 8
	case FtUint16, FtInt16:
		return 16
	case FtUint24, FtInt24:
		return 24
	case FtUint32, FtInt32, FtFrameNum:
		return 32
	case FtUint40:
		return 40
	case FtUint48:
		return 48
	case FtUint56:
		return 56
	case FtUint64, FtInt64:
		return 64
	}
	return 0
}

// Base is the display base of integer fields.
type Base uint8

const (
	BaseNone Base = iota
	BaseDec
	BaseHex
	BaseOct
	BaseDecHex
	BaseHexDec
)

// FieldID indexes the global field registry.
type FieldID int32

// FieldDef describes a filterable field (Wireshark's header_field_info).
type FieldDef struct {
	ID      FieldID
	Abbrev  string
	Name    string
	Type    FieldType
	Base    Base
	Bitmask uint64
	Blurb   string
	// Bitwidth of the containing value for bitmask display (8, 16, 32...).
	// Defaults to Type.Bits().
	ParentBits int
	VS         map[uint64]string
	TFS        *TrueFalse
	Unit       string
	Proto      *Proto // protocol the field belongs to
	shift      uint
}

// TrueFalse holds display strings for boolean fields.
type TrueFalse struct{ True, False string }

var (
	TFSSet     = &TrueFalse{"Set", "Not set"}
	TFSYesNo   = &TrueFalse{"Yes", "No"}
	TFSPresent = &TrueFalse{"Present", "Not present"}
	TFSTrue    = &TrueFalse{"True", "False"}
)

// Proto is a registered protocol. Every protocol is also a field of type
// FtProtocol with the protocol's filter name.
type Proto struct {
	Name   string    // "Transmission Control Protocol"
	Short  string    // "TCP"
	Filter string    // "tcp"
	HF     *FieldDef // the protocol's own field
	Index  int
	// Enabled may be toggled by the user (Analyze → Enabled Protocols).
	Enabled bool
}

type registry struct {
	mu       sync.RWMutex
	fields   []*FieldDef
	byAbbrev map[string]*FieldDef
	protos   []*Proto
	byFilter map[string]*Proto
}

var reg = &registry{byAbbrev: map[string]*FieldDef{}, byFilter: map[string]*Proto{}}

// RegisterProto registers a protocol and its protocol field.
func RegisterProto(name, short, filter string) *Proto {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if p, ok := reg.byFilter[filter]; ok {
		panic("dissect: duplicate protocol " + filter + " (" + p.Name + ")")
	}
	p := &Proto{Name: name, Short: short, Filter: filter, Index: len(reg.protos), Enabled: true}
	f := &FieldDef{Abbrev: filter, Name: name, Type: FtProtocol, Proto: p}
	reg.addLocked(f)
	p.HF = f
	reg.protos = append(reg.protos, p)
	reg.byFilter[filter] = p
	return p
}

func (r *registry) addLocked(f *FieldDef) {
	if _, dup := r.byAbbrev[f.Abbrev]; dup {
		panic("dissect: duplicate field " + f.Abbrev)
	}
	f.ID = FieldID(len(r.fields))
	if f.Bitmask != 0 {
		for f.Bitmask>>f.shift&1 == 0 {
			f.shift++
		}
	}
	if f.ParentBits == 0 {
		f.ParentBits = f.Type.Bits()
	}
	r.fields = append(r.fields, f)
	r.byAbbrev[f.Abbrev] = f
}

// FieldOpt customizes a field at registration.
type FieldOpt func(*FieldDef)

func WithBase(b Base) FieldOpt             { return func(f *FieldDef) { f.Base = b } }
func WithMask(m uint64) FieldOpt           { return func(f *FieldDef) { f.Bitmask = m } }
func WithParentBits(n int) FieldOpt        { return func(f *FieldDef) { f.ParentBits = n } }
func WithVS(vs map[uint64]string) FieldOpt { return func(f *FieldDef) { f.VS = vs } }
func WithTFS(t *TrueFalse) FieldOpt        { return func(f *FieldDef) { f.TFS = t } }
func WithBlurb(s string) FieldOpt          { return func(f *FieldDef) { f.Blurb = s } }
func WithUnit(s string) FieldOpt           { return func(f *FieldDef) { f.Unit = s } }

// Field registers a field belonging to p.
func (p *Proto) Field(abbrev, name string, t FieldType, opts ...FieldOpt) *FieldDef {
	f := &FieldDef{Abbrev: abbrev, Name: name, Type: t, Proto: p}
	if t.IsInteger() && t != FtBool {
		f.Base = BaseDec
	}
	for _, o := range opts {
		o(f)
	}
	reg.mu.Lock()
	reg.addLocked(f)
	reg.mu.Unlock()
	return f
}

// LookupField returns the field with the given abbreviation.
func LookupField(abbrev string) *FieldDef {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	return reg.byAbbrev[abbrev]
}

// FieldByID returns a field by id.
func FieldByID(id FieldID) *FieldDef {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	if int(id) < 0 || int(id) >= len(reg.fields) {
		return nil
	}
	return reg.fields[id]
}

// NumFields is the size of the registry.
func NumFields() int {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	return len(reg.fields)
}

// LookupProto returns a protocol by filter name.
func LookupProto(filter string) *Proto {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	return reg.byFilter[filter]
}

// Protocols returns all protocols sorted by filter name.
func Protocols() []*Proto {
	reg.mu.RLock()
	out := append([]*Proto(nil), reg.protos...)
	reg.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Filter < out[j].Filter })
	return out
}

// Fields returns all registered fields sorted by abbreviation.
func Fields() []*FieldDef {
	reg.mu.RLock()
	out := append([]*FieldDef(nil), reg.fields...)
	reg.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Abbrev < out[j].Abbrev })
	return out
}

// FieldsWithPrefix returns fields whose abbreviation starts with prefix.
func FieldsWithPrefix(prefix string) []*FieldDef {
	var out []*FieldDef
	for _, f := range Fields() {
		if strings.HasPrefix(f.Abbrev, prefix) {
			out = append(out, f)
		}
	}
	return out
}

func (f *FieldDef) String() string { return fmt.Sprintf("%s (%s)", f.Abbrev, f.Type) }

// Masked extracts the field value from its containing integer.
func (f *FieldDef) Masked(v uint64) uint64 {
	if f.Bitmask == 0 {
		return v
	}
	return (v & f.Bitmask) >> f.shift
}
