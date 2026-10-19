package dissect

import "sort"

// FragRef points at the bytes of one fragment: by offset into a captured
// frame (cheap, re-read from the file when needed) or, for bytes from a
// derived data source, as a copy.
type FragRef struct {
	Frame uint32
	Off   int32 // offset in the frame's bytes
	Len   int32
	Data  []byte // copy when the bytes are not in the frame itself
	Pos   int32  // position of the fragment in the reassembled data
}

// Ref records n bytes at off of tvb, belonging at position pos of a
// reassembled buffer.
func (pi *PacketInfo) Ref(tvb *Tvb, off, n, pos int) FragRef {
	r := FragRef{Frame: pi.Num, Off: int32(tvb.base + off), Len: int32(n), Pos: int32(pos)}
	if tvb.ds != 0 {
		r.Data = append([]byte(nil), tvb.Bytes(off, n)...)
	}
	return r
}

// FragBytes returns the bytes a FragRef points at.
func (s *Session) FragBytes(r FragRef) []byte {
	if r.Data != nil {
		return r.Data
	}
	if s.FrameBytes == nil {
		return nil
	}
	b := s.FrameBytes(r.Frame)
	end := int(r.Off) + int(r.Len)
	if end > len(b) || r.Off < 0 {
		return nil
	}
	return b[r.Off:end]
}

// Assemble concatenates fragments at their positions into a buffer of
// total bytes. Overlapping data is taken from the later fragment.
func (s *Session) Assemble(frags []FragRef, total int) []byte {
	buf := make([]byte, total)
	for _, f := range frags {
		b := s.FragBytes(f)
		if int(f.Pos) < total {
			copy(buf[f.Pos:], b)
		}
	}
	return buf
}

// FragSet collects fragments of one datagram (IP fragments and similar).
type FragSet struct {
	Frags    []FragRef
	HaveLast bool
	Total    int
}

// Add records a fragment; last marks the final fragment. It reports
// whether the data from 0 to Total is now complete.
func (f *FragSet) Add(r FragRef, last bool) bool {
	f.Frags = append(f.Frags, r)
	if last {
		f.HaveLast = true
		f.Total = int(r.Pos + r.Len)
	}
	if !f.HaveLast {
		return false
	}
	sorted := append([]FragRef(nil), f.Frags...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Pos < sorted[j].Pos })
	covered := 0
	for _, fr := range sorted {
		if int(fr.Pos) > covered {
			return false
		}
		covered = max(covered, int(fr.Pos+fr.Len))
	}
	return covered >= f.Total
}

// Reassembled is the per-frame record of a completed reassembly.
type Reassembled struct {
	Frags []FragRef
	Total int
}

// Frames lists the distinct frames of a reassembly in order.
func (r *Reassembled) Frames() []uint32 {
	var out []uint32
	seen := map[uint32]bool{}
	for _, f := range r.Frags {
		if !seen[f.Frame] {
			seen[f.Frame] = true
			out = append(out, f.Frame)
		}
	}
	return out
}
