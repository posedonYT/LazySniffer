package proto

import (
	"fmt"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

// TCPDesegment enables reassembly of PDUs spanning segments
// (tcp.desegment_tcp_streams).
var TCPDesegment = true

const maxReasm = 16 << 20

var (
	hfTCPSegments     = protoTCP.Field("tcp.segments", "Reassembled TCP Segments", d.FtNone)
	hfTCPSegment      = protoTCP.Field("tcp.segment", "TCP Segment", d.FtFrameNum)
	hfTCPSegmentCount = protoTCP.Field("tcp.segment.count", "Segment count", d.FtUint32)
	hfTCPReasmLen     = protoTCP.Field("tcp.reassembled.length", "Reassembled TCP length", d.FtUint32)
	hfTCPReasmData    = protoTCP.Field("tcp.reassembled.data", "Reassembled TCP Data", d.FtBytes)
	hfTCPReasmIn      = protoTCP.Field("tcp.reassembled_in", "Reassembled PDU in frame", d.FtFrameNum)
	hfTCPSegmentData  = protoTCP.Field("tcp.segment_data", "TCP segment data", d.FtBytes)
)

// tcpReasmFlow is per-direction reassembly state of the first pass.
type tcpReasmFlow struct {
	app     *d.Handle // protocol the connection switched to (CONNECT, Upgrade)
	handle  *d.Handle // dissector that asked for more data
	pending []d.FragRef
	have    int
	need    int // bytes needed in pending before retrying; -1 = one more segment
	frames  []uint32
	nextSeq uint32
	nextSet bool
}

const (
	reasmDirect   uint8 = iota // dissect the payload as is
	reasmPartial               // payload belongs to a PDU completed in another frame
	reasmComplete              // reassembled PDU(s) are dissected in this frame
	reasmRetrans               // retransmitted data, not dissected again
)

type tcpReasmFrame struct {
	mode    uint8
	in      uint32 // frame where the pending data was reassembled
	frags   []d.FragRef
	total   int
	tailOff int // offset where an unfinished PDU starts (-1 none)
	handle  *d.Handle
}

func reasmRecord(pi *d.PacketInfo) *tcpReasmFrame {
	r, _ := pi.Sess.FrameData(protoTCP, pi.Num, 1).(*tcpReasmFrame)
	return r
}

func (r *tcpReasmFlow) reset() {
	r.pending, r.have, r.need, r.frames = nil, 0, 0, nil
}

// finish links frames that contributed to pending data to the frame that
// reassembled it.
func (r *tcpReasmFlow) finish(sess *d.Session, in uint32) {
	for _, f := range r.frames {
		if rec, ok := sess.FrameData(protoTCP, f, 1).(*tcpReasmFrame); ok && rec.in == 0 && f != in {
			rec.in = in
		}
	}
}

func trimFrags(frags []d.FragRef, from int) []d.FragRef {
	var out []d.FragRef
	for _, f := range frags {
		end := int(f.Pos + f.Len)
		if end <= from {
			continue
		}
		if int(f.Pos) < from {
			cut := from - int(f.Pos)
			f.Off += int32(cut)
			f.Len -= int32(cut)
			if f.Data != nil {
				f.Data = f.Data[cut:]
			}
			f.Pos = int32(from)
		}
		f.Pos -= int32(from)
		out = append(out, f)
	}
	return out
}

// tcpPayload dissects a segment's payload with reassembly.
func tcpPayload(payload *d.Tvb, pi *d.PacketInfo, tree, tt *d.Node, fd *tcpFrame, st *tcpConv, seq uint32, segLen int) {
	sport, dport := pi.SrcPort, pi.DstPort
	if !TCPDesegment || st == nil {
		dispatchPorts(TCPPortTable, TCPHeur, payload, pi, tree, sport, dport)
		return
	}
	sess := pi.Sess
	if !pi.Visited {
		tcpReasmFirstPass(payload, pi, tree, fd, &st.flows[fd.dir].reasm, seq, segLen)
		return
	}
	rec := reasmRecord(pi)
	if rec == nil {
		dispatchPorts(TCPPortTable, TCPHeur, payload, pi, tree, sport, dport)
		pi.TakeDesegment()
		return
	}
	switch rec.mode {
	case reasmRetrans:
		n, _ := tt.AddBytes(hfTCPSegmentData, payload, 0, payload.Len())
		n.SetText("Retransmitted TCP segment data (%d bytes)", payload.Len())
	case reasmPartial:
		n, _ := tt.AddBytes(hfTCPSegmentData, payload, 0, payload.Len())
		n.SetText("TCP segment data (%d bytes)", payload.Len())
		if rec.in != 0 {
			tt.AddGenerated(hfTCPReasmIn, d.Value{U: uint64(rec.in)}).SetLink(rec.in)
		}
		reasmInfo(pi, rec)
	case reasmDirect:
		callPayload(rec.handle, payload, pi, tree, sport, dport)
		pi.TakeDesegment()
		if rec.tailOff >= 0 && rec.tailOff < payload.Len() {
			n, _ := tt.AddBytes(hfTCPSegmentData, payload, rec.tailOff, payload.Len()-rec.tailOff)
			n.SetText("TCP segment data (%d bytes)", payload.Len()-rec.tailOff)
			if rec.in != 0 {
				tt.AddGenerated(hfTCPReasmIn, d.Value{U: uint64(rec.in)}).SetLink(rec.in)
			}
			if rec.tailOff == 0 {
				reasmInfo(pi, rec)
			}
		}
	case reasmComplete:
		buf := sess.Assemble(rec.frags, rec.total)
		rt := pi.AddSource("Reassembled TCP", buf)
		addSegmentsTree(tree, rec, rt)
		callPayload(rec.handle, rt, pi, tree, sport, dport)
		pi.TakeDesegment()
		if rec.tailOff >= 0 && rec.in != 0 {
			tt.AddGenerated(hfTCPReasmIn, d.Value{U: uint64(rec.in)}).SetLink(rec.in)
		}
	}
}

// reasmInfo labels a segment that belongs to a PDU reassembled later; in
// the second pass the frame that completes the PDU is known.
func reasmInfo(pi *d.PacketInfo, rec *tcpReasmFrame) {
	if rec.in != 0 {
		pi.AppendInfo(" [TCP PDU reassembled in %d]", rec.in)
		return
	}
	pi.AppendInfo(" [TCP segment of a reassembled PDU]")
}

func callPayload(h *d.Handle, tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node, sport, dport uint32) {
	if h != nil {
		pi.Call(h, tvb, tree)
		return
	}
	dispatchPorts(TCPPortTable, TCPHeur, tvb, pi, tree, sport, dport)
}

func tcpReasmFirstPass(payload *d.Tvb, pi *d.PacketInfo, tree *d.Node, fd *tcpFrame, r *tcpReasmFlow, seq uint32, segLen int) {
	sess := pi.Sess
	sport, dport := pi.SrcPort, pi.DstPort
	store := func(rec *tcpReasmFrame) { sess.SetFrameData(protoTCP, pi.Num, 1, rec) }
	retrans := fd.analysis&(taRetrans|taFastRetrans|taSpurious|taOutOfOrder) != 0
	if r.nextSet && seq != r.nextSeq && !seqGT(seq, r.nextSeq) && (retrans || seqLT(seq, r.nextSeq)) {
		// Data we have already delivered (or out of order): do not feed it twice.
		store(&tcpReasmFrame{mode: reasmRetrans, tailOff: -1})
		return
	}
	if r.pending != nil && r.nextSet && seq != r.nextSeq {
		// A gap: the pending PDU can never be completed.
		r.reset()
	}
	r.nextSeq, r.nextSet = seq+uint32(segLen), true

	if r.pending == nil {
		use := r.handle
		if r.app != nil {
			use = r.app
		}
		callPayload(use, payload, pi, tree, sport, dport)
		off, more, h, ok := pi.TakeDesegment()
		if !ok || off >= payload.Len() || off < 0 {
			if use != nil {
				// Later passes must pick the same dissector.
				store(&tcpReasmFrame{mode: reasmDirect, tailOff: -1, handle: use})
			}
			return
		}
		r.handle = h
		rest := payload.Len() - off
		r.pending = []d.FragRef{pi.Ref(payload, off, rest, 0)}
		r.have = rest
		r.need = -1
		if more > 0 {
			r.need = rest + more
		}
		r.frames = []uint32{pi.Num}
		store(&tcpReasmFrame{mode: reasmDirect, tailOff: off, handle: h})
		return
	}

	r.pending = append(r.pending, pi.Ref(payload, 0, payload.Len(), r.have))
	r.have += payload.Len()
	r.frames = append(r.frames, pi.Num)
	if r.have > maxReasm {
		r.finish(sess, 0)
		store(&tcpReasmFrame{mode: reasmPartial, tailOff: -1})
		r.reset()
		return
	}
	if r.need >= 0 && r.have < r.need {
		store(&tcpReasmFrame{mode: reasmPartial, tailOff: -1})
		return
	}
	frags := append([]d.FragRef(nil), r.pending...)
	buf := sess.Assemble(frags, r.have)
	rt := pi.AddSource("Reassembled TCP", buf)
	h := r.handle
	callPayload(h, rt, pi, tree, sport, dport)
	off, more, h2, ok := pi.TakeDesegment()
	if h2 != nil {
		h = h2
	}
	if !ok {
		store(&tcpReasmFrame{mode: reasmComplete, frags: frags, total: r.have, tailOff: -1, handle: h})
		r.finish(sess, pi.Num)
		r.reset()
		return
	}
	if off <= 0 {
		// Still not enough: keep waiting for more segments.
		if more > 0 {
			r.need = r.have + more
		} else {
			r.need = -1
		}
		store(&tcpReasmFrame{mode: reasmPartial, tailOff: -1})
		return
	}
	// PDUs before off are complete here; an unfinished one starts at off.
	store(&tcpReasmFrame{mode: reasmComplete, frags: frags, total: r.have, tailOff: off, handle: h})
	r.finish(sess, pi.Num)
	r.pending = trimFrags(frags, off)
	r.have -= off
	r.need = -1
	if more > 0 {
		r.need = r.have + more
	}
	r.frames = []uint32{pi.Num}
}

func addSegmentsTree(tree *d.Node, rec *tcpReasmFrame, tvb *d.Tvb) {
	var parts []string
	for _, f := range rec.frags {
		parts = append(parts, fmt.Sprintf("#%d(%d)", f.Frame, f.Len))
	}
	st := tree.AddValue(hfTCPSegments, tvb, 0, tvb.Len(), d.Value{}).SetGenerated()
	st.SetText("[%d Reassembled TCP Segments (%d bytes): %s]", len(rec.frags), rec.total, strings.Join(parts, ", "))
	for _, f := range rec.frags {
		st.AddValue(hfTCPSegment, tvb, int(f.Pos), int(f.Len), d.Value{U: uint64(f.Frame)}).
			SetText("[Frame: %d, payload: %d-%d (%d bytes)]", f.Frame, f.Pos, f.Pos+f.Len-1, f.Len).SetLink(f.Frame)
	}
	st.AddGenerated(hfTCPSegmentCount, d.Value{U: uint64(len(rec.frags))})
	st.AddGenerated(hfTCPReasmLen, d.Value{U: uint64(rec.total)})
	st.AddValue(hfTCPReasmData, tvb, 0, tvb.Len(), d.Value{B: tvb.Raw()}).SetGenerated()
}

// SetTCPAppHandle hands the rest of the frame's TCP connection to h, from
// the next segment on (after HTTP CONNECT or an Upgrade). First pass only.
func SetTCPAppHandle(pi *d.PacketInfo, h *d.Handle) {
	if setTLSAppHandle(pi, h) {
		return
	}
	if pi.Visited || pi.Conv == nil {
		return
	}
	st, _ := pi.Conv.Data(protoTCP).(*tcpConv)
	if st == nil {
		return
	}
	for i := range st.flows {
		st.flows[i].reasm.app = h
		st.flows[i].reasm.handle = nil
	}
}

// TCPDissectPDUs splits a TCP payload into PDUs. fixedLen bytes are needed
// to learn a PDU's length from pduLen; PDUs spanning segments are
// reassembled automatically. It returns the bytes consumed.
func TCPDissectPDUs(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node, fixedLen int,
	pduLen func(tvb *d.Tvb, off int) int, dissect func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int) int {
	off := 0
	for off < tvb.Len() {
		rem := tvb.Remaining(off)
		if rem < fixedLen {
			pi.Desegment(off, fixedLen-rem)
			return tvb.Len()
		}
		n := pduLen(tvb, off)
		if n <= 0 {
			return off
		}
		if rem < n {
			pi.Desegment(off, n-rem)
			return tvb.Len()
		}
		dissect(tvb.Sub(off, n), pi, tree)
		off += n
	}
	return off
}
