package proto

import "testing"

func FuzzQPACK(f *testing.F) {
	f.Add([]byte{0x02, 0x00, 0xd1, 0xd7, 0x51, 0x01, '/', 0x80}, []byte{0x3f, 0xe1, 0x1f, 0x48, 'x', '-', 'c', 'u', 's', 't', 'o', 'm', 'x', 0x05, 'h', 'e', 'l', 'l', 'o'})
	f.Fuzz(func(t *testing.T, block, enc []byte) {
		d := &qpackDec{maxCap: 4096}
		d.feed(enc)
		d.decode(block)
		d.feed(enc)
		d.decode(block)
	})
}

func FuzzH3Feed(f *testing.F) {
	f.Add([]byte{0x00, 0x04, 0x04, 0x01, 0x40, 0x00, 0x07, 0x10}, []byte{0x01, 0x04, 0x00, 0x00, 0xd1, 0xd7})
	f.Fuzz(func(t *testing.T, a, b []byte) {
		c := newH3Conn()
		recs := c.feed(1, 2, 0, a, false)
		recs = append(recs, c.feed(1, 3, 0, a, true)...)
		recs = append(recs, c.feed(0, 0, 0, b, false)...)
		recs = append(recs, c.feed(0, 0, uint64(len(b)), b, true)...)
		recs = append(recs, c.feed(0, 6, 0, append([]byte{2}, a...), false)...)
		_ = recs
	})
}
