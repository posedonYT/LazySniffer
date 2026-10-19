package proto

import (
	"errors"
	"fmt"

	"golang.org/x/net/http2/hpack"
)

// qpackHF is a decoded header field. (The static table below uses the
// same type; it is the RFC 9204 table.)
type qpackHF struct {
	Name  string
	Value string
}

var errQPACK = errors.New("qpack: malformed")

// qpackInt reads a prefix-coded integer (RFC 7541 §5.1).
func qpackInt(b []byte, n int) (v uint64, used int, err error) {
	if len(b) == 0 {
		return 0, 0, errQPACK
	}
	mask := byte(1<<uint(n) - 1)
	v = uint64(b[0] & mask)
	used = 1
	if v < uint64(mask) {
		return v, used, nil
	}
	var shift uint
	for {
		if used >= len(b) || shift > 56 {
			return 0, 0, errQPACK
		}
		c := b[used]
		used++
		v += uint64(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			return v, used, nil
		}
	}
}

// qpackString reads a string literal whose Huffman flag is bit hbit of
// b[0] and whose length uses the low n bits.
func qpackString(b []byte, n int) (s string, used int, err error) {
	if len(b) == 0 {
		return "", 0, errQPACK
	}
	huff := b[0]&(1<<uint(n)) != 0
	l, u, err := qpackInt(b, n)
	if err != nil || uint64(len(b)-u) < l {
		return "", 0, errQPACK
	}
	raw := b[u : u+int(l)]
	if huff {
		s, err = hpack.HuffmanDecodeToString(raw)
		if err != nil {
			return "", 0, err
		}
	} else {
		s = string(raw)
	}
	return s, u + int(l), nil
}

// qpackDec is the decoder state of one direction (its encoder stream).
type qpackDec struct {
	dyn      []qpackHF // oldest first
	dropped  uint64
	size     uint64
	capacity uint64
	maxCap   uint64 // from SETTINGS_QPACK_MAX_TABLE_CAPACITY
	inserted uint64
	pending  []byte // unfinished encoder-stream instruction
}

func (d *qpackDec) evict() {
	for d.size > d.capacity && len(d.dyn) > 0 {
		d.size -= uint64(len(d.dyn[0].Name)+len(d.dyn[0].Value)) + 32
		d.dyn = d.dyn[1:]
		d.dropped++
	}
}

func (d *qpackDec) insert(hf qpackHF) {
	d.dyn = append(d.dyn, hf)
	d.size += uint64(len(hf.Name)+len(hf.Value)) + 32
	d.inserted++
	d.evict()
}

func (d *qpackDec) abs(i uint64) (qpackHF, bool) {
	if i < d.dropped || i-d.dropped >= uint64(len(d.dyn)) {
		return qpackHF{}, false
	}
	return d.dyn[i-d.dropped], true
}

// feed processes encoder stream bytes and returns readable instruction
// descriptions (for display).
func (d *qpackDec) feed(data []byte) (descr []string) {
	b := append(d.pending, data...)
	d.pending = nil
	for len(b) > 0 {
		used, desc, ok := d.instruction(b)
		if !ok {
			d.pending = append([]byte(nil), b...)
			return
		}
		descr = append(descr, desc)
		b = b[used:]
	}
	return
}

func (d *qpackDec) instruction(b []byte) (int, string, bool) {
	switch {
	case b[0]&0x80 != 0: // insert with name reference
		static := b[0]&0x40 != 0
		idx, u, err := qpackInt(b, 6)
		if err != nil {
			return 0, "", false
		}
		val, u2, err := qpackString(b[u:], 7)
		if err != nil {
			return 0, "", false
		}
		var name string
		if static {
			if idx >= uint64(len(qpackStatic)) {
				return len(b), "invalid static index", true
			}
			name = qpackStatic[idx].Name
		} else if e, ok := d.abs(d.inserted - 1 - idx); ok && idx < d.inserted {
			name = e.Name
		}
		d.insert(qpackHF{name, val})
		return u + u2, fmt.Sprintf("Insert With Name Reference: %s: %s", name, val), true
	case b[0]&0x40 != 0: // insert with literal name
		name, u, err := qpackString(b, 5)
		if err != nil {
			return 0, "", false
		}
		val, u2, err := qpackString(b[u:], 7)
		if err != nil {
			return 0, "", false
		}
		d.insert(qpackHF{name, val})
		return u + u2, fmt.Sprintf("Insert With Literal Name: %s: %s", name, val), true
	case b[0]&0x20 != 0: // set capacity
		c, u, err := qpackInt(b, 5)
		if err != nil {
			return 0, "", false
		}
		d.capacity = c
		d.evict()
		return u, fmt.Sprintf("Set Dynamic Table Capacity: %d", c), true
	default: // duplicate
		idx, u, err := qpackInt(b, 5)
		if err != nil {
			return 0, "", false
		}
		if idx < d.inserted {
			if e, ok := d.abs(d.inserted - 1 - idx); ok {
				d.insert(e)
			}
		}
		return u, fmt.Sprintf("Duplicate: %d", idx), true
	}
}

// decode decodes a field section. When the section needs inserts that did
// not arrive yet it returns blocked with the required insert count.
func (d *qpackDec) decode(b []byte) (fields []qpackHF, ric uint64, blocked bool, err error) {
	enc, u, err := qpackInt(b, 8)
	if err != nil {
		return nil, 0, false, err
	}
	b = b[u:]
	if enc != 0 {
		maxEntries := d.maxCap / 32
		full := 2 * maxEntries
		if full == 0 || enc > full {
			return nil, 0, false, errQPACK
		}
		maxVal := d.inserted + maxEntries
		wrapped := maxVal / full * full
		ric = wrapped + enc - 1
		if ric > maxVal {
			if ric <= full {
				return nil, 0, false, errQPACK
			}
			ric -= full
		}
	}
	if len(b) == 0 {
		return nil, ric, false, errQPACK
	}
	sign := b[0]&0x80 != 0
	delta, u, err := qpackInt(b, 7)
	if err != nil {
		return nil, ric, false, err
	}
	b = b[u:]
	base := ric + delta
	if sign {
		if delta+1 > ric {
			return nil, ric, false, errQPACK
		}
		base = ric - delta - 1
	}
	if ric > d.inserted {
		return nil, ric, true, nil
	}
	dyn := func(abs uint64) (qpackHF, error) {
		if e, ok := d.abs(abs); ok {
			return e, nil
		}
		return qpackHF{}, errQPACK
	}
	for len(b) > 0 {
		switch {
		case b[0]&0x80 != 0: // indexed field line
			static := b[0]&0x40 != 0
			idx, u, err := qpackInt(b, 6)
			if err != nil {
				return fields, ric, false, err
			}
			b = b[u:]
			if static {
				if idx >= uint64(len(qpackStatic)) {
					return fields, ric, false, errQPACK
				}
				fields = append(fields, qpackStatic[idx])
			} else {
				if idx+1 > base {
					return fields, ric, false, errQPACK
				}
				e, err := dyn(base - 1 - idx)
				if err != nil {
					return fields, ric, false, err
				}
				fields = append(fields, e)
			}
		case b[0]&0xf0 == 0x10: // indexed with post-base index
			idx, u, err := qpackInt(b, 4)
			if err != nil {
				return fields, ric, false, err
			}
			b = b[u:]
			e, err := dyn(base + idx)
			if err != nil {
				return fields, ric, false, err
			}
			fields = append(fields, e)
		case b[0]&0xc0 == 0x40: // literal with name reference
			static := b[0]&0x10 != 0
			idx, u, err := qpackInt(b, 4)
			if err != nil {
				return fields, ric, false, err
			}
			b = b[u:]
			val, u2, err := qpackString(b, 7)
			if err != nil {
				return fields, ric, false, err
			}
			b = b[u2:]
			var name string
			if static {
				if idx >= uint64(len(qpackStatic)) {
					return fields, ric, false, errQPACK
				}
				name = qpackStatic[idx].Name
			} else {
				if idx+1 > base {
					return fields, ric, false, errQPACK
				}
				e, err := dyn(base - 1 - idx)
				if err != nil {
					return fields, ric, false, err
				}
				name = e.Name
			}
			fields = append(fields, qpackHF{name, val})
		case b[0]&0xf0 == 0x00: // literal with post-base name reference
			idx, u, err := qpackInt(b, 3)
			if err != nil {
				return fields, ric, false, err
			}
			b = b[u:]
			val, u2, err := qpackString(b, 7)
			if err != nil {
				return fields, ric, false, err
			}
			b = b[u2:]
			e, err := dyn(base + idx)
			if err != nil {
				return fields, ric, false, err
			}
			fields = append(fields, qpackHF{e.Name, val})
		case b[0]&0xe0 == 0x20: // literal with literal name
			name, u, err := qpackString(b, 3)
			if err != nil {
				return fields, ric, false, err
			}
			b = b[u:]
			val, u2, err := qpackString(b, 7)
			if err != nil {
				return fields, ric, false, err
			}
			b = b[u2:]
			fields = append(fields, qpackHF{name, val})
		default:
			return fields, ric, false, errQPACK
		}
	}
	return fields, ric, false, nil
}
