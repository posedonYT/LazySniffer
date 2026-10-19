package stats

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/store"
)

// RTPStream is one direction of a media stream.
type RTPStream struct {
	Src, Dst    string // "ip:port"
	SSRC        uint32
	PayloadType uint8
	Packets     int
	Expected    int
	Lost        int
	SeqErrors   int
	MinDelta    float64 // ms
	MeanDelta   float64 // ms
	MaxDelta    float64 // ms
	MeanJitter  float64 // ms
	MaxJitter   float64 // ms
	First, Last uint32  // frame numbers
	Start       float64 // seconds since the first frame of the capture
	Duration    float64
	SetupFrame  uint32
	Frames      []uint32
	ClockRate   int
	problematic bool
}

// LostPct is the loss in percent.
func (s *RTPStream) LostPct() float64 {
	if s.Expected <= 0 {
		return 0
	}
	return 100 * float64(s.Lost) / float64(s.Expected)
}

// Filter selects the stream's packets.
func (s *RTPStream) Filter() string {
	return fmt.Sprintf("rtp.ssrc == 0x%x && ip.src == %s && udp.srcport == %s", s.SSRC, hostOf(s.Src), portOf(s.Src))
}

func hostOf(hp string) string { i := strings.LastIndexByte(hp, ':'); return hp[:i] }
func portOf(hp string) string { i := strings.LastIndexByte(hp, ':'); return hp[i+1:] }

var rtpClock = map[uint8]int{0: 8000, 3: 8000, 4: 8000, 5: 8000, 6: 16000, 7: 8000, 8: 8000, 9: 8000, 10: 44100, 11: 44100, 13: 8000, 14: 90000, 15: 8000, 18: 8000, 26: 90000, 31: 90000, 32: 90000, 34: 90000}

type rtpPkt struct {
	frame uint32
	ts    float64 // arrival, seconds
	seq   uint16
	rtpTS uint32
	setup uint32
}

type rtpKey struct {
	src, dst string
	ssrc     uint32
	pt       uint8
}

// RTPStreams analyses every RTP stream in the capture (RFC 3550 jitter).
func RTPStreams(ctx context.Context, c *store.Capture) ([]*RTPStream, error) {
	names := []string{"rtp.ssrc", "rtp.p_type", "rtp.seq", "rtp.timestamp", "rtp.setup-frame"}
	fd := make([]*dissect.FieldDef, len(names))
	want := make([]bool, dissect.NumFields())
	for i, n := range names {
		if fd[i] = dissect.LookupField(n); fd[i] == nil {
			return nil, fmt.Errorf("field %s missing", n)
		}
		want[fd[i].ID] = true
	}
	parts := make([]map[rtpKey][]rtpPkt, engine.Workers())
	for i := range parts {
		parts[i] = map[rtpKey][]rtpPkt{}
	}
	t0 := c.Frame(1).TS
	err := engine.Each(ctx, c, dissect.Options{Want: want}, engine.AllFrames(c), func(w int, num uint32, pi *dissect.PacketInfo) {
		ssrc, ok := pi.Tree.First(fd[0])
		if !ok {
			return
		}
		pt, _ := pi.Tree.First(fd[1])
		seq, _ := pi.Tree.First(fd[2])
		rts, _ := pi.Tree.First(fd[3])
		setup, _ := pi.Tree.First(fd[4])
		k := rtpKey{src: fmt.Sprintf("%s:%d", pi.Src, pi.SrcPort), dst: fmt.Sprintf("%s:%d", pi.Dst, pi.DstPort), ssrc: uint32(ssrc.V.U), pt: uint8(pt.V.U)}
		parts[w][k] = append(parts[w][k], rtpPkt{frame: num, ts: float64(pi.TS-t0) / 1e9, seq: uint16(seq.V.U), rtpTS: uint32(rts.V.U), setup: uint32(setup.V.U)})
	})
	if err != nil {
		return nil, err
	}
	merged := map[rtpKey][]rtpPkt{}
	for _, p := range parts {
		for k, v := range p {
			merged[k] = append(merged[k], v...)
		}
	}
	var out []*RTPStream
	for k, pk := range merged {
		sort.Slice(pk, func(i, j int) bool { return pk[i].frame < pk[j].frame })
		s := &RTPStream{Src: k.src, Dst: k.dst, SSRC: k.ssrc, PayloadType: k.pt, Packets: len(pk), First: pk[0].frame, Last: pk[len(pk)-1].frame,
			Start: pk[0].ts, Duration: pk[len(pk)-1].ts - pk[0].ts, SetupFrame: pk[0].setup, ClockRate: rtpClock[k.pt]}
		if s.ClockRate == 0 {
			s.ClockRate = 8000
		}
		var cycles uint32
		maxSeq := uint32(pk[0].seq)
		baseSeq := uint32(pk[0].seq)
		var jitter, maxJit, maxDelta, sumJit, sumDelta float64
		minDelta := math.Inf(1)
		for i, p := range pk {
			s.Frames = append(s.Frames, p.frame)
			if i == 0 {
				continue
			}
			prev := pk[i-1]
			// extended sequence number (handles 16-bit wrap)
			d := int(p.seq) - int(prev.seq)
			if d != 1 && !(prev.seq == 0xffff && p.seq == 0) {
				s.SeqErrors++
			}
			if p.seq < prev.seq && prev.seq-p.seq > 0x8000 {
				cycles += 1 << 16
			}
			if ext := cycles + uint32(p.seq); ext > maxSeq {
				maxSeq = ext
			}
			delta := (p.ts - prev.ts) * 1000
			maxDelta = math.Max(maxDelta, delta)
			minDelta = math.Min(minDelta, delta)
			sumDelta += delta
			// RFC 3550 A.8: D = (Rj - Ri) - (Sj - Si) in RTP timestamp units
			dd := (p.ts-prev.ts)*float64(s.ClockRate) - float64(int32(p.rtpTS-prev.rtpTS))
			jitter += (math.Abs(dd) - jitter) / 16
			maxJit = math.Max(maxJit, jitter)
			sumJit += jitter
		}
		n := float64(max(len(pk)-1, 1))
		if len(pk) > 1 {
			s.MinDelta = minDelta
		}
		s.MeanDelta = sumDelta / n
		s.Expected = int(maxSeq-baseSeq) + 1
		s.Lost = s.Expected - s.Packets
		s.MaxDelta = maxDelta
		s.MeanJitter = sumJit / n / float64(s.ClockRate) * 1000
		s.MaxJitter = maxJit / float64(s.ClockRate) * 1000
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].First < out[j].First })
	return out, nil
}

// VoIPCall is a SIP dialog.
type VoIPCall struct {
	CallID   string
	From, To string
	Start    float64
	Duration float64
	State    string
	Frames   []uint32 // SIP packets
	First    uint32
	Streams  []*RTPStream
	Invite   bool
}

// VoIPCalls groups SIP messages by Call-ID and attaches RTP streams.
func VoIPCalls(ctx context.Context, c *store.Capture) ([]*VoIPCall, error) {
	names := []string{"sip.Call-ID", "sip.Method", "sip.Status-Code", "sip.CSeq.method", "sip.from.user", "sip.to.user", "sip.From", "sip.To"}
	fd := make([]*dissect.FieldDef, len(names))
	want := make([]bool, dissect.NumFields())
	for i, n := range names {
		if fd[i] = dissect.LookupField(n); fd[i] == nil {
			return nil, fmt.Errorf("field %s missing", n)
		}
		want[fd[i].ID] = true
	}
	type ev struct {
		frame  uint32
		ts     float64
		callID string
		method string
		code   int
		cseqM  string
		from   string
		to     string
	}
	parts := make([][]ev, engine.Workers())
	t0 := c.Frame(1).TS
	err := engine.Each(ctx, c, dissect.Options{Want: want}, engine.AllFrames(c), func(w int, num uint32, pi *dissect.PacketInfo) {
		id, ok := pi.Tree.First(fd[0])
		if !ok {
			return
		}
		e := ev{frame: num, ts: float64(pi.TS-t0) / 1e9, callID: id.V.S}
		if v, ok := pi.Tree.First(fd[1]); ok {
			e.method = v.V.S
		}
		if v, ok := pi.Tree.First(fd[2]); ok {
			e.code = int(v.V.U)
		}
		if v, ok := pi.Tree.First(fd[3]); ok {
			e.cseqM = v.V.S
		}
		if v, ok := pi.Tree.First(fd[4]); ok {
			e.from = v.V.S
		}
		if v, ok := pi.Tree.First(fd[5]); ok {
			e.to = v.V.S
		}
		if e.from == "" {
			if v, ok := pi.Tree.First(fd[6]); ok {
				e.from = v.V.S
			}
		}
		if e.to == "" {
			if v, ok := pi.Tree.First(fd[7]); ok {
				e.to = v.V.S
			}
		}
		parts[w] = append(parts[w], e)
	})
	if err != nil {
		return nil, err
	}
	var evs []ev
	for _, p := range parts {
		evs = append(evs, p...)
	}
	sort.Slice(evs, func(i, j int) bool { return evs[i].frame < evs[j].frame })
	calls := map[string]*VoIPCall{}
	var order []*VoIPCall
	byFrame := map[uint32]*VoIPCall{}
	for _, e := range evs {
		call := calls[e.callID]
		if call == nil {
			call = &VoIPCall{CallID: e.callID, Start: e.ts, First: e.frame, State: "CALL SETUP"}
			calls[e.callID] = call
			order = append(order, call)
		}
		byFrame[e.frame] = call
		call.Frames = append(call.Frames, e.frame)
		call.Duration = e.ts - call.Start
		if call.From == "" {
			call.From, call.To = e.from, e.to
		}
		switch {
		case e.method == "INVITE":
			call.Invite = true
		case e.method == "BYE":
			call.State = "COMPLETED"
		case e.method == "CANCEL":
			call.State = "CANCELED"
		case e.code == 180 || e.code == 183:
			if call.State == "CALL SETUP" {
				call.State = "RINGING"
			}
		case e.code == 200 && e.cseqM == "INVITE":
			if call.State == "CALL SETUP" || call.State == "RINGING" {
				call.State = "IN CALL"
			}
		case e.code >= 400 && e.cseqM == "INVITE":
			call.State = "REJECTED"
		}
	}
	streams, err := RTPStreams(ctx, c)
	if err != nil {
		return nil, err
	}
	for _, s := range streams {
		if call := byFrame[s.SetupFrame]; call != nil {
			call.Streams = append(call.Streams, s)
		}
	}
	// Only dialogs that start with an INVITE are calls.
	var out []*VoIPCall
	for _, call := range order {
		if call.Invite {
			out = append(out, call)
		}
	}
	return out, nil
}
