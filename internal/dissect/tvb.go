package dissect

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Tvb is a view of packet bytes ("testy virtual buffer" in Wireshark terms).
// Accessors panic with a BoundsError when reading past the end; dissector
// calls recover and mark the packet as malformed or truncated.
type Tvb struct {
	data     []byte // captured bytes visible through this view
	reported int    // length the packet claims (>= len(data) when truncated)
	ds       uint8  // data source index
	base     int    // offset of data[0] within the data source
}

// BoundsError is raised by Tvb accessors.
type BoundsError struct {
	// Short means the bytes exist in the real packet but were not captured
	// (snaplen); otherwise the packet itself is malformed.
	Short bool
	Off   int
	Len   int
}

func (e BoundsError) Error() string {
	if e.Short {
		return fmt.Sprintf("packet size limited during capture (offset %d, length %d)", e.Off, e.Len)
	}
	return fmt.Sprintf("malformed packet (offset %d, length %d)", e.Off, e.Len)
}

// NewTvb creates a top-level view of a data source.
func NewTvb(data []byte, reported int, ds uint8) *Tvb {
	if reported < len(data) {
		reported = len(data)
	}
	return &Tvb{data: data, reported: reported, ds: ds}
}

// Len is the number of captured bytes.
func (t *Tvb) Len() int { return len(t.data) }

// Reported is the length the packet claims for this view.
func (t *Tvb) Reported() int { return t.reported }

// Remaining returns captured bytes from off to the end (0 if off is past it).
func (t *Tvb) Remaining(off int) int {
	if off >= len(t.data) {
		return 0
	}
	return len(t.data) - off
}

// DS is the data source index of the view.
func (t *Tvb) DS() uint8 { return t.ds }

// Base is the absolute offset of the view within its data source.
func (t *Tvb) Base() int { return t.base }

// Raw returns the view's captured bytes.
func (t *Tvb) Raw() []byte { return t.data }

func (t *Tvb) check(off, n int) {
	if off < 0 || n < 0 || off+n > len(t.data) {
		panic(BoundsError{Short: off >= 0 && n >= 0 && off+n <= t.reported, Off: t.base + off, Len: n})
	}
}

// Has reports whether n bytes at off are captured.
func (t *Tvb) Has(off, n int) bool { return off >= 0 && n >= 0 && off+n <= len(t.data) }

// Sub returns a view starting at off. A negative n means "to the end".
func (t *Tvb) Sub(off, n int) *Tvb {
	if n < 0 {
		if off > len(t.data) {
			t.check(off, 0)
		}
		return &Tvb{data: t.data[off:], reported: t.reported - off, ds: t.ds, base: t.base + off}
	}
	// Allow a sub-view that extends past the captured bytes but within the
	// reported length: the view is truncated and accessors report "short".
	if off < 0 || off > len(t.data) || off+n > t.reported {
		t.check(off, n)
	}
	end := off + n
	if end > len(t.data) {
		end = len(t.data)
	}
	return &Tvb{data: t.data[off:end:end], reported: n, ds: t.ds, base: t.base + off}
}

func (t *Tvb) U8(off int) uint8 {
	t.check(off, 1)
	return t.data[off]
}

func (t *Tvb) U16(off int) uint16 {
	t.check(off, 2)
	return binary.BigEndian.Uint16(t.data[off:])
}

func (t *Tvb) U16LE(off int) uint16 {
	t.check(off, 2)
	return binary.LittleEndian.Uint16(t.data[off:])
}

func (t *Tvb) U24(off int) uint32 {
	t.check(off, 3)
	d := t.data[off:]
	return uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
}

func (t *Tvb) U24LE(off int) uint32 {
	t.check(off, 3)
	d := t.data[off:]
	return uint32(d[2])<<16 | uint32(d[1])<<8 | uint32(d[0])
}

func (t *Tvb) U32(off int) uint32 {
	t.check(off, 4)
	return binary.BigEndian.Uint32(t.data[off:])
}

func (t *Tvb) U32LE(off int) uint32 {
	t.check(off, 4)
	return binary.LittleEndian.Uint32(t.data[off:])
}

func (t *Tvb) U48(off int) uint64 {
	t.check(off, 6)
	d := t.data[off:]
	return uint64(d[0])<<40 | uint64(d[1])<<32 | uint64(d[2])<<24 | uint64(d[3])<<16 | uint64(d[4])<<8 | uint64(d[5])
}

func (t *Tvb) U64(off int) uint64 {
	t.check(off, 8)
	return binary.BigEndian.Uint64(t.data[off:])
}

func (t *Tvb) U64LE(off int) uint64 {
	t.check(off, 8)
	return binary.LittleEndian.Uint64(t.data[off:])
}

// UintN reads an n-byte big- or little-endian integer (n <= 8).
func (t *Tvb) UintN(off, n int, little bool) uint64 {
	t.check(off, n)
	var v uint64
	for i := 0; i < n; i++ {
		if little {
			v |= uint64(t.data[off+i]) << (8 * uint(i))
		} else {
			v = v<<8 | uint64(t.data[off+i])
		}
	}
	return v
}

// Bytes returns n bytes at off (aliasing the packet buffer).
func (t *Tvb) Bytes(off, n int) []byte {
	if n < 0 {
		n = t.Remaining(off)
	}
	t.check(off, n)
	return t.data[off : off+n : off+n]
}

// String returns n bytes at off as a string.
func (t *Tvb) String(off, n int) string { return string(t.Bytes(off, n)) }

// Stringz reads a NUL-terminated string starting at off, at most max bytes
// (max < 0 means to the end). It returns the string and bytes consumed
// including the terminator if present.
func (t *Tvb) Stringz(off, max int) (string, int) {
	end := len(t.data)
	if max >= 0 && off+max < end {
		end = off + max
	}
	t.check(off, 0)
	i := bytes.IndexByte(t.data[off:end], 0)
	if i < 0 {
		return string(t.data[off:end]), end - off
	}
	return string(t.data[off : off+i]), i + 1
}

// Find returns the offset of needle at or after off, or -1.
func (t *Tvb) Find(off int, needle []byte) int {
	if off > len(t.data) {
		return -1
	}
	i := bytes.Index(t.data[off:], needle)
	if i < 0 {
		return -1
	}
	return off + i
}

// LineEnd finds the end of a text line starting at off. It returns the
// line length (without terminator) and the offset of the next line, or
// (-1, -1) when no terminator was found.
func (t *Tvb) LineEnd(off int) (lineLen, next int) {
	if off > len(t.data) {
		return -1, -1
	}
	i := bytes.IndexByte(t.data[off:], '\n')
	if i < 0 {
		return -1, -1
	}
	l := i
	if l > 0 && t.data[off+l-1] == '\r' {
		l--
	}
	return l, off + i + 1
}
