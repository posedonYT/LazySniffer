package dissect

import (
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Value is a typed field value. Integers, bools, IPv4 addresses, frame
// numbers and times (nanoseconds) live in U; floats in F; strings in S;
// bytes, MAC, IPv6 and GUID values in B.
type Value struct {
	T FieldType
	U uint64
	F float64
	S string
	B []byte
}

func UintValue(t FieldType, u uint64) Value { return Value{T: t, U: u} }
func IntValue(t FieldType, i int64) Value   { return Value{T: t, U: uint64(i)} }
func BoolValue(b bool) Value {
	v := Value{T: FtBool}
	if b {
		v.U = 1
	}
	return v
}
func StringValue(s string) Value              { return Value{T: FtString, S: s} }
func BytesValue(t FieldType, b []byte) Value  { return Value{T: t, B: b} }
func FloatValue(t FieldType, f float64) Value { return Value{T: t, F: f} }
func TimeValue(ns int64) Value                { return Value{T: FtAbsTime, U: uint64(ns)} }
func RelTimeValue(ns int64) Value             { return Value{T: FtRelTime, U: uint64(ns)} }

// Int returns the value as a signed integer.
func (v Value) Int() int64 { return int64(v.U) }

// Bool reports whether a boolean or integer value is non-zero.
func (v Value) Bool() bool { return v.U != 0 }

func hexWidth(bits int) int {
	if bits <= 0 {
		return 1
	}
	return (bits + 3) / 4
}

// FormatUint renders an integer value in the field's base.
func FormatUint(f *FieldDef, u uint64) string {
	if f.Base == BaseNone && !f.Type.IsSigned() {
		return strconv.FormatUint(u, 10)
	}
	bits := f.Type.Bits()
	if f.Bitmask != 0 {
		bits = 64 - leadingZeros(f.Bitmask>>f.shift)
	}
	switch f.Base {
	case BaseHex:
		return fmt.Sprintf("0x%0*x", hexWidth(bits), u)
	case BaseOct:
		return fmt.Sprintf("0%o", u)
	case BaseDecHex:
		return fmt.Sprintf("%d (0x%0*x)", u, hexWidth(bits), u)
	case BaseHexDec:
		return fmt.Sprintf("0x%0*x (%d)", hexWidth(bits), u, u)
	}
	if f.Type.IsSigned() {
		return strconv.FormatInt(signExtend(u, f.Type.Bits()), 10)
	}
	return strconv.FormatUint(u, 10)
}

func leadingZeros(x uint64) int {
	n := 0
	for i := 63; i >= 0 && x>>uint(i)&1 == 0; i-- {
		n++
	}
	return n
}

func signExtend(u uint64, bits int) int64 {
	if bits <= 0 || bits >= 64 {
		return int64(u)
	}
	shift := uint(64 - bits)
	return int64(u<<shift) >> shift
}

// Display renders the value as shown in the packet details pane.
func (f *FieldDef) Display(v Value) string {
	switch f.Type {
	case FtNone, FtProtocol:
		return ""
	case FtBool:
		tfs := f.TFS
		if tfs == nil {
			tfs = TFSTrue
		}
		if v.U != 0 {
			return tfs.True
		}
		return tfs.False
	case FtChar:
		if v.U >= 0x20 && v.U < 0x7f {
			return fmt.Sprintf("'%c'", rune(v.U))
		}
		return fmt.Sprintf("'\\x%02x'", v.U)
	case FtFrameNum:
		return strconv.FormatUint(v.U, 10)
	case FtFloat, FtDouble:
		return strconv.FormatFloat(v.F, 'g', -1, 64)
	case FtAbsTime:
		return FormatAbsTime(int64(v.U), false)
	case FtRelTime:
		return FormatRelTime(int64(v.U)) + " seconds"
	case FtString:
		return EscapeString(v.S)
	case FtBytes, FtOID:
		if len(v.B) == 0 {
			return "<MISSING>"
		}
		return TruncHex(v.B, 36)
	case FtEther:
		return FormatEther(v.B)
	case FtEUI64:
		return FormatColonHex(v.B)
	case FtIPv4:
		return FormatIPv4(uint32(v.U))
	case FtIPv6:
		return FormatIPv6(v.B)
	case FtGUID:
		return FormatGUID(v.B)
	}
	if f.Type.IsInteger() {
		s := FormatUint(f, v.U)
		if f.VS != nil {
			if name, ok := f.VS[v.U]; ok {
				if f.Base == BaseNone {
					return name
				}
				return name + " (" + s + ")"
			}
			return "Unknown (" + s + ")"
		}
		if f.Unit != "" {
			s += " " + f.Unit
		}
		return s
	}
	return ""
}

// FilterString renders the value as a display filter literal.
func (f *FieldDef) FilterString(v Value) string {
	switch f.Type {
	case FtNone, FtProtocol:
		return ""
	case FtBool:
		if v.U != 0 {
			return "1"
		}
		return "0"
	case FtString:
		return strconv.Quote(v.S)
	case FtBytes, FtOID:
		return FormatColonHex(v.B)
	case FtEther, FtEUI64:
		return FormatColonHex(v.B)
	case FtIPv4:
		return FormatIPv4(uint32(v.U))
	case FtIPv6:
		return FormatIPv6(v.B)
	case FtGUID:
		return FormatGUID(v.B)
	case FtFloat, FtDouble:
		return strconv.FormatFloat(v.F, 'g', -1, 64)
	case FtAbsTime:
		return strconv.Quote(FormatAbsTime(int64(v.U), false))
	case FtRelTime:
		return FormatRelTime(int64(v.U))
	case FtChar:
		switch {
		case v.U >= 0x20 && v.U < 0x7f && v.U != '\'' && v.U != '\\':
			return fmt.Sprintf("'%c'", rune(v.U))
		case v.U == 0:
			return "'\\0'"
		}
		return fmt.Sprintf("'\\x%02x'", v.U)
	}
	if f.Type.IsSigned() {
		return strconv.FormatInt(signExtend(v.U, f.Type.Bits()), 10)
	}
	if f.Base == BaseHex || f.Base == BaseHexDec {
		bits := f.Type.Bits()
		if f.Bitmask != 0 {
			bits = 64 - leadingZeros(f.Bitmask>>f.shift)
		}
		return fmt.Sprintf("0x%0*x", hexWidth(bits), v.U)
	}
	return strconv.FormatUint(v.U, 10)
}

// FilterExpr is "abbrev == value" (or just "abbrev" for labels/protocols).
func (f *FieldDef) FilterExpr(v Value) string {
	s := f.FilterString(v)
	if s == "" {
		return f.Abbrev
	}
	return f.Abbrev + " == " + s
}

// BitPattern renders ".... ..1. ...." for a bitmask field.
func (f *FieldDef) BitPattern(raw uint64) string {
	bits := f.ParentBits
	if bits == 0 {
		bits = 8
	}
	var b strings.Builder
	for i := bits - 1; i >= 0; i-- {
		if f.Bitmask>>uint(i)&1 == 1 {
			if raw>>uint(i)&1 == 1 {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		} else {
			b.WriteByte('.')
		}
		if i%4 == 0 && i != 0 {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

func FormatEther(b []byte) string {
	if len(b) != 6 {
		return FormatColonHex(b)
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func FormatColonHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	out := make([]byte, 0, len(b)*3)
	for i, c := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, "0123456789abcdef"[c>>4], "0123456789abcdef"[c&15])
	}
	return string(out)
}

func TruncHex(b []byte, max int) string {
	if len(b) > max {
		return hex.EncodeToString(b[:max]) + "…"
	}
	return hex.EncodeToString(b)
}

func FormatIPv4(u uint32) string {
	return strconv.Itoa(int(u>>24)) + "." + strconv.Itoa(int(u>>16&0xff)) + "." +
		strconv.Itoa(int(u>>8&0xff)) + "." + strconv.Itoa(int(u&0xff))
}

func FormatIPv6(b []byte) string {
	if len(b) != 16 {
		return FormatColonHex(b)
	}
	return netip.AddrFrom16([16]byte(b)).String()
}

func FormatGUID(b []byte) string {
	if len(b) != 16 {
		return FormatColonHex(b)
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]),
		uint16(b[4])<<8|uint16(b[5]), uint16(b[6])<<8|uint16(b[7]), b[8:10], b[10:16])
}

// FormatAbsTime renders a timestamp like Wireshark's frame.time.
func FormatAbsTime(ns int64, utc bool) string {
	t := time.Unix(0, ns)
	if utc {
		t = t.UTC()
	}
	return t.Format("Jan _2, 2006 15:04:05.000000000 MST")
}

// FormatRelTime renders nanoseconds as seconds with nanosecond precision.
func FormatRelTime(ns int64) string {
	sign := ""
	if ns < 0 {
		sign = "-"
		ns = -ns
	}
	return fmt.Sprintf("%s%d.%09d", sign, ns/1e9, ns%1e9)
}

// EscapeString renders a string with non-printable characters escaped.
func EscapeString(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, "\\x%02x", s[i])
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// Float32 converts raw bits to a float value.
func Float32(bits uint32) float64 { return float64(math.Float32frombits(bits)) }
