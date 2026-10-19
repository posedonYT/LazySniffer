package dfilter

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/poseydon/lazysniffer/internal/dissect"
)

// kind is the evaluation type of a value.
type kind uint8

const (
	kNone kind = iota // label/presence only
	kUint
	kInt
	kFloat
	kBool
	kString
	kBytes
	kIPv4
	kIPv6
	kTime
	kRelTime
	kProto // protocol: bytes of the protocol's data
)

func (k kind) String() string {
	return [...]string{"label", "unsigned integer", "signed integer", "floating point", "boolean",
		"string", "byte sequence", "IPv4 address", "IPv6 address", "date and time", "time offset", "protocol"}[k]
}

func (k kind) numeric() bool {
	return k == kUint || k == kInt || k == kFloat || k == kBool || k == kTime || k == kRelTime
}

func (k kind) bytesLike() bool { return k == kBytes || k == kProto || k == kString || k == kIPv6 }

// val is an evaluated value.
type val struct {
	k    kind
	u    uint64 // uint, bool, ipv4
	i    int64  // int, time, reltime
	f    float64
	s    string
	b    []byte
	bits int // prefix length for ipv4/ipv6 literals (32/128 = exact)
}

func kindOf(t dissect.FieldType) kind {
	switch {
	case t == dissect.FtBool:
		return kBool
	case t.IsUnsigned():
		return kUint
	case t.IsSigned():
		return kInt
	}
	switch t {
	case dissect.FtFloat, dissect.FtDouble:
		return kFloat
	case dissect.FtString:
		return kString
	case dissect.FtBytes, dissect.FtEther, dissect.FtGUID, dissect.FtOID, dissect.FtEUI64:
		return kBytes
	case dissect.FtIPv4:
		return kIPv4
	case dissect.FtIPv6:
		return kIPv6
	case dissect.FtAbsTime:
		return kTime
	case dissect.FtRelTime:
		return kRelTime
	case dissect.FtProtocol:
		return kProto
	}
	return kNone
}

func fromField(f *dissect.FieldDef, v dissect.Value) val {
	k := kindOf(f.Type)
	switch k {
	case kUint, kBool:
		return val{k: k, u: v.U}
	case kInt:
		bits := f.Type.Bits()
		shift := uint(64 - bits)
		return val{k: k, i: int64(v.U<<shift) >> shift}
	case kFloat:
		return val{k: k, f: v.F}
	case kString:
		return val{k: k, s: v.S}
	case kBytes, kProto:
		return val{k: k, b: v.B}
	case kIPv4:
		return val{k: k, u: v.U, bits: 32}
	case kIPv6:
		return val{k: k, b: v.B, bits: 128}
	case kTime, kRelTime:
		return val{k: k, i: int64(v.U)}
	}
	return val{k: kNone}
}

func (v val) asFloat() float64 {
	switch v.k {
	case kUint, kBool, kIPv4:
		return float64(v.u)
	case kInt, kTime, kRelTime:
		return float64(v.i)
	case kFloat:
		return v.f
	}
	return 0
}

func (v val) asBytes() []byte {
	switch v.k {
	case kString:
		return []byte(v.s)
	case kIPv4:
		return []byte{byte(v.u >> 24), byte(v.u >> 16), byte(v.u >> 8), byte(v.u)}
	}
	return v.b
}

func (v val) asString() string {
	switch v.k {
	case kString:
		return v.s
	case kBytes, kProto:
		return string(v.b)
	case kUint, kBool:
		return strconv.FormatUint(v.u, 10)
	case kInt:
		return strconv.FormatInt(v.i, 10)
	case kFloat:
		return strconv.FormatFloat(v.f, 'g', -1, 64)
	case kIPv4:
		return dissect.FormatIPv4(uint32(v.u))
	case kIPv6:
		return dissect.FormatIPv6(v.b)
	case kTime:
		return dissect.FormatAbsTime(v.i, false)
	case kRelTime:
		return dissect.FormatRelTime(v.i)
	}
	return ""
}

// cmp compares two values of compatible kinds. ok is false when the kinds
// cannot be ordered.
func cmp(a, b val) (int, bool) {
	switch {
	case a.k == kIPv4 && b.k == kIPv4:
		bits := min(a.bits, b.bits)
		mask := uint64(0xffffffff) << uint(32-bits) & 0xffffffff
		x, y := a.u&mask, b.u&mask
		return cmpU(x, y), true
	case a.k == kIPv6 && b.k == kIPv6:
		bits := min(a.bits, b.bits)
		return cmpPrefix(a.b, b.b, bits), true
	case a.k.numeric() && b.k.numeric():
		if a.k == kFloat || b.k == kFloat {
			x, y := a.asFloat(), b.asFloat()
			switch {
			case x < y:
				return -1, true
			case x > y:
				return 1, true
			}
			return 0, true
		}
		if (a.k == kUint || a.k == kBool) && (b.k == kUint || b.k == kBool) {
			return cmpU(a.u, b.u), true
		}
		return cmpI(a.asInt(), b.asInt()), true
	case a.k == kString && b.k == kString:
		return strings.Compare(a.s, b.s), true
	case a.k.bytesLike() && b.k.bytesLike():
		return bytes.Compare(a.asBytes(), b.asBytes()), true
	}
	return 0, false
}

func (v val) asInt() int64 {
	switch v.k {
	case kUint, kBool:
		if v.u > math.MaxInt64 {
			return math.MaxInt64
		}
		return int64(v.u)
	case kFloat:
		return int64(v.f)
	}
	return v.i
}

func cmpU(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpI(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpPrefix(a, b []byte, bits int) int {
	for i := 0; i < len(a) && i < len(b) && bits > 0; i++ {
		m := byte(0xff)
		if bits < 8 {
			m = 0xff << uint(8-bits)
		}
		x, y := a[i]&m, b[i]&m
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
		bits -= 8
	}
	return 0
}

// ---- literal parsing ----

func parseUint(s string) (uint64, error) {
	s = strings.ReplaceAll(s, "_", "")
	switch {
	case strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X"):
		return strconv.ParseUint(s[2:], 16, 64)
	case strings.HasPrefix(s, "0b") || strings.HasPrefix(s, "0B"):
		return strconv.ParseUint(s[2:], 2, 64)
	case len(s) > 1 && s[0] == '0':
		return strconv.ParseUint(s[1:], 8, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}

// parseBytes accepts aa:bb:cc, aa-bb-cc, aa.bb.cc, aabb.ccdd and plain hex.
func parseBytes(s string) ([]byte, bool) {
	if s == "" {
		return nil, false
	}
	var sep byte
	for _, c := range []byte{':', '-', '.'} {
		if strings.IndexByte(s, c) >= 0 {
			sep = c
			break
		}
	}
	if sep == 0 {
		if len(s)%2 != 0 {
			if len(s) == 1 {
				s = "0" + s
			} else {
				return nil, false
			}
		}
		b, err := hex.DecodeString(s)
		return b, err == nil
	}
	var out []byte
	for _, part := range strings.Split(s, string(sep)) {
		if len(part) == 0 || len(part)%2 != 0 && len(part) != 1 {
			return nil, false
		}
		if len(part) == 1 {
			part = "0" + part
		}
		b, err := hex.DecodeString(part)
		if err != nil {
			return nil, false
		}
		out = append(out, b...)
	}
	return out, true
}

var timeLayouts = []string{
	"Jan _2, 2006 15:04:05.999999999 MST",
	"Jan _2, 2006 15:04:05.999999999",
	"Jan _2, 2006 15:04:05",
	"Jan _2, 2006 15:04",
	"2006-01-02 15:04:05.999999999 MST",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04",
	"2006-01-02",
}

func parseTime(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, " UTC") || strings.HasSuffix(s, "Z") {
		for _, l := range timeLayouts {
			if t, err := time.Parse(l, s); err == nil {
				return t.UnixNano(), true
			}
		}
	}
	for _, l := range timeLayouts {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t.UnixNano(), true
		}
	}
	// Seconds since the epoch.
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return int64(f * 1e9), true
	}
	return 0, false
}

// literal converts literal text to a value of the given field's kind.
func literal(f *dissect.FieldDef, k kind, text string, quoted bool) (val, error) {
	switch k {
	case kUint, kInt, kBool:
		t := strings.TrimSpace(text)
		if k == kBool {
			switch strings.ToLower(t) {
			case "true":
				return val{k: kBool, u: 1}, nil
			case "false":
				return val{k: kBool, u: 0}, nil
			}
		}
		if f != nil && f.VS != nil {
			for num, name := range f.VS {
				if strings.EqualFold(name, t) {
					return val{k: k, u: num, i: int64(num)}, nil
				}
			}
		}
		if f != nil && f.TFS != nil {
			if strings.EqualFold(f.TFS.True, t) {
				return val{k: k, u: 1}, nil
			}
			if strings.EqualFold(f.TFS.False, t) {
				return val{k: k, u: 0}, nil
			}
		}
		if k == kInt && strings.HasPrefix(t, "-") {
			u, err := parseUint(t[1:])
			if err != nil {
				return val{}, fmt.Errorf("\"%s\" is not a valid number", text)
			}
			return val{k: kInt, i: -int64(u)}, nil
		}
		u, err := parseUint(t)
		if err != nil {
			if fl, ferr := strconv.ParseFloat(t, 64); ferr == nil {
				return val{k: kFloat, f: fl}, nil
			}
			return val{}, fmt.Errorf("\"%s\" is not a valid number", text)
		}
		if k == kBool && u > 1 {
			return val{}, fmt.Errorf("\"%s\" is not a valid boolean (use 1/0 or True/False)", text)
		}
		return val{k: k, u: u, i: int64(u)}, nil
	case kFloat:
		fl, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
		if err != nil {
			return val{}, fmt.Errorf("\"%s\" is not a valid floating point number", text)
		}
		return val{k: kFloat, f: fl}, nil
	case kString:
		return val{k: kString, s: text}, nil
	case kBytes, kProto:
		if quoted {
			return val{k: kBytes, b: []byte(text)}, nil
		}
		if b, ok := parseBytes(text); ok {
			return val{k: kBytes, b: b}, nil
		}
		if f != nil && f.Type == dissect.FtEther {
			return val{}, fmt.Errorf("\"%s\" is not a valid hardware address", text)
		}
		return val{}, fmt.Errorf("\"%s\" is not a valid byte string", text)
	case kIPv4:
		addr, bits := text, 32
		if a, b, ok := strings.Cut(text, "/"); ok {
			n, err := strconv.Atoi(b)
			if err != nil || n < 0 || n > 32 {
				return val{}, fmt.Errorf("\"%s\" is not a valid IPv4 prefix length", b)
			}
			addr, bits = a, n
		}
		ip, err := netip.ParseAddr(addr)
		if err != nil || !ip.Is4() {
			return val{}, fmt.Errorf("\"%s\" is not a valid IPv4 address", text)
		}
		a4 := ip.As4()
		return val{k: kIPv4, u: uint64(a4[0])<<24 | uint64(a4[1])<<16 | uint64(a4[2])<<8 | uint64(a4[3]), bits: bits}, nil
	case kIPv6:
		addr, bits := text, 128
		if a, b, ok := strings.Cut(text, "/"); ok {
			n, err := strconv.Atoi(b)
			if err != nil || n < 0 || n > 128 {
				return val{}, fmt.Errorf("\"%s\" is not a valid IPv6 prefix length", b)
			}
			addr, bits = a, n
		}
		ip, err := netip.ParseAddr(addr)
		if err != nil || !ip.Is6() {
			return val{}, fmt.Errorf("\"%s\" is not a valid IPv6 address", text)
		}
		a16 := ip.As16()
		return val{k: kIPv6, b: a16[:], bits: bits}, nil
	case kTime:
		ns, ok := parseTime(text)
		if !ok {
			return val{}, fmt.Errorf("\"%s\" is not a valid absolute time; use e.g. \"2024-01-31 12:00:00\"", text)
		}
		return val{k: kTime, i: ns}, nil
	case kRelTime:
		fl, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
		if err != nil {
			return val{}, fmt.Errorf("\"%s\" is not a valid time offset in seconds", text)
		}
		return val{k: kRelTime, i: int64(math.Round(fl * 1e9))}, nil
	case kNone:
		return val{}, fmt.Errorf("%s is a label and cannot be compared with a value", f.Abbrev)
	}
	return val{}, fmt.Errorf("cannot convert \"%s\"", text)
}

// guessLiteral types a literal compared with something of unknown type.
func guessLiteral(text string, quoted bool) val {
	if quoted {
		return val{k: kString, s: text}
	}
	if u, err := parseUint(text); err == nil {
		return val{k: kUint, u: u, i: int64(u)}
	}
	if f, err := strconv.ParseFloat(text, 64); err == nil {
		return val{k: kFloat, f: f}
	}
	if v, err := literal(nil, kIPv4, text, false); err == nil {
		return v
	}
	if v, err := literal(nil, kIPv6, text, false); err == nil {
		return v
	}
	if b, ok := parseBytes(text); ok {
		return val{k: kBytes, b: b}
	}
	return val{k: kString, s: text}
}
