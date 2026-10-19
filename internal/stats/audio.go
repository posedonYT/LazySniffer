package stats

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/store"
)

// ulaw decodes one G.711 µ-law byte.
func ulaw(b byte) int16 {
	b = ^b
	t := (int(b&0x0f) << 3) + 0x84
	t <<= (b & 0x70) >> 4
	if b&0x80 != 0 {
		return int16(0x84 - t)
	}
	return int16(t - 0x84)
}

// alaw decodes one G.711 A-law byte.
func alaw(b byte) int16 {
	b ^= 0x55
	t := int(b&0x0f) << 4
	seg := int(b&0x70) >> 4
	switch seg {
	case 0:
		t += 8
	case 1:
		t += 0x108
	default:
		t += 0x108
		t <<= seg - 1
	}
	if b&0x80 != 0 {
		return int16(t)
	}
	return int16(-t)
}

// RTPAudio decodes a G.711 stream to 16-bit mono PCM at 8 kHz. Lost
// packets become silence, so the audio keeps its original timing.
func RTPAudio(ctx context.Context, c *store.Capture, s *RTPStream) ([]int16, error) {
	var dec func(byte) int16
	switch s.PayloadType {
	case 0:
		dec = ulaw
	case 8:
		dec = alaw
	default:
		return nil, fmt.Errorf("payload type %d cannot be decoded (only G.711 PCMU/PCMA)", s.PayloadType)
	}
	pay := dissect.LookupField("rtp.payload")
	seq := dissect.LookupField("rtp.seq")
	ts := dissect.LookupField("rtp.timestamp")
	want := make([]bool, dissect.NumFields())
	want[pay.ID], want[seq.ID], want[ts.ID] = true, true, true
	w := c.Session().NewWorker(dissect.Options{Want: want})
	type pkt struct {
		ts   uint32
		data []byte
	}
	var pk []pkt
	for _, num := range s.Frames {
		pi := w.Dissect(c.Input(num))
		p, _ := pi.Tree.First(pay)
		t, _ := pi.Tree.First(ts)
		pk = append(pk, pkt{ts: uint32(t.V.U), data: append([]byte(nil), p.V.B...)})
	}
	sort.SliceStable(pk, func(i, j int) bool { return int32(pk[i].ts-pk[j].ts) < 0 })
	var out []int16
	var next uint32
	for i, p := range pk {
		if i > 0 && int32(p.ts-next) > 0 {
			gap := int(p.ts - next)
			if gap < 8000*30 { // ignore absurd jumps
				out = append(out, make([]int16, gap)...)
			}
		}
		for _, b := range p.data {
			out = append(out, dec(b))
		}
		next = p.ts + uint32(len(p.data))
	}
	return out, nil
}

// WriteWAV writes 16-bit mono PCM.
func WriteWAV(w interface{ Write([]byte) (int, error) }, pcm []int16, rate int) error {
	hdr := make([]byte, 44)
	copy(hdr[0:], "RIFF")
	binary.LittleEndian.PutUint32(hdr[4:], uint32(36+len(pcm)*2))
	copy(hdr[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(hdr[16:], 16)
	binary.LittleEndian.PutUint16(hdr[20:], 1)
	binary.LittleEndian.PutUint16(hdr[22:], 1)
	binary.LittleEndian.PutUint32(hdr[24:], uint32(rate))
	binary.LittleEndian.PutUint32(hdr[28:], uint32(rate*2))
	binary.LittleEndian.PutUint16(hdr[32:], 2)
	binary.LittleEndian.PutUint16(hdr[34:], 16)
	copy(hdr[36:], "data")
	binary.LittleEndian.PutUint32(hdr[40:], uint32(len(pcm)*2))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	buf := make([]byte, len(pcm)*2)
	for i, v := range pcm {
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(v))
	}
	_, err := w.Write(buf)
	return err
}
