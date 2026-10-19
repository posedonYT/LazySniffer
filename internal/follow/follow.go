// Package follow reconstructs the application data of a TCP or UDP stream
// (Wireshark's Follow Stream).
package follow

import (
	"context"
	"fmt"
	"sort"

	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/dissect"
	_ "github.com/poseydon/lazysniffer/internal/dissect/proto" // field registry must exist before the lookups below
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/store"
)

// Kind is the followed transport.
type Kind uint8

const (
	TCP Kind = iota
	UDP
	TLS  // decrypted TLS application data of a TCP stream
	HTTP // like TLS when the stream was decrypted, else the TCP payload
)

func (k Kind) String() string {
	switch k {
	case UDP:
		return "UDP"
	case TLS:
		return "TLS"
	case HTTP:
		return "HTTP"
	}
	return "TCP"
}

// Filter returns the display filter selecting the stream.
func (k Kind) Filter(stream uint32) string {
	if k == UDP {
		return fmt.Sprintf("udp.stream eq %d", stream)
	}
	return fmt.Sprintf("tcp.stream eq %d", stream)
}

// Transport reports the transport protocol of the followed stream.
func (k Kind) Transport() Kind {
	if k == UDP {
		return UDP
	}
	return TCP
}

// Chunk is a run of bytes sent by one peer.
type Chunk struct {
	FromServer bool
	Frame      uint32
	TS         int64
	Data       []byte
	Missing    int // bytes missing in the capture before this chunk
}

// Stream is the reconstructed conversation.
type Stream struct {
	Kind        Kind
	Index       uint32
	Client      string // "10.0.0.1:40000"
	Server      string
	Chunks      []Chunk
	ClientBytes int
	ServerBytes int
	ClientPkts  int
	ServerPkts  int
	Frames      []uint32
}

// Turns counts direction changes (Wireshark's "turns").
func (s *Stream) Turns() int {
	n := 0
	for i := 1; i < len(s.Chunks); i++ {
		if s.Chunks[i].FromServer != s.Chunks[i-1].FromServer {
			n++
		}
	}
	return n
}

type seg struct {
	frame   uint32
	ts      int64
	seq     uint32
	data    []byte
	syn     bool
	server  bool
	sawData bool
}

var (
	fTCPStream = dissect.LookupField("tcp.stream")
	fUDPStream = dissect.LookupField("udp.stream")
	fSeqRaw    = dissect.LookupField("tcp.seq_raw")
	fPayload   = dissect.LookupField("tcp.payload")
	fUDPPay    = dissect.LookupField("udp.payload")
	fSYN       = dissect.LookupField("tcp.flags.syn")
	fTLSDec    = dissect.LookupField("tls.decrypted.data")
)

// Build collects stream index of kind k from the capture.
func Build(ctx context.Context, c *store.Capture, k Kind, index uint32) (*Stream, error) {
	flt, err := dfilter.Compile(k.Filter(index))
	if err != nil {
		return nil, err
	}
	frames, err := engine.Filter(ctx, c, flt, 1, uint32(c.Count()), nil)
	if err != nil {
		return nil, err
	}
	want := make([]bool, dissect.NumFields())
	for _, f := range []*dissect.FieldDef{fTCPStream, fUDPStream, fSeqRaw, fPayload, fUDPPay, fSYN, fTLSDec} {
		if f != nil {
			want[f.ID] = true
		}
	}
	w := c.Session().NewWorker(dissect.Options{Want: want})
	st := &Stream{Kind: k, Index: index, Frames: frames}
	var segs []seg
	var dec []Chunk
	var conv *dissect.Conversation
	for _, num := range frames {
		pi := w.Dissect(c.Input(num))
		if conv == nil && pi.Conv != nil {
			conv = pi.Conv
			st.Client = endpoint(conv.AddrA, conv.PortA)
			st.Server = endpoint(conv.AddrB, conv.PortB)
		}
		server := conv != nil && !conv.FromA(pi.Src, pi.SrcPort)
		s := seg{frame: num, ts: pi.TS, server: server}
		if k != UDP {
			for _, v := range pi.Tree.Values(fTLSDec) {
				dec = append(dec, Chunk{FromServer: server, Frame: num, TS: pi.TS, Data: append([]byte(nil), v.V.B...)})
			}
			if v, ok := pi.Tree.First(fSeqRaw); ok {
				s.seq = uint32(v.V.U)
			}
			if v, ok := pi.Tree.First(fSYN); ok {
				s.syn = v.V.U != 0
			}
			if v, ok := pi.Tree.First(fPayload); ok {
				s.data = append([]byte(nil), v.V.B...)
			}
		} else if v, ok := pi.Tree.First(fUDPPay); ok {
			s.data = append([]byte(nil), v.V.B...)
		}
		segs = append(segs, s)
		if server {
			st.ServerPkts++
		} else {
			st.ClientPkts++
		}
	}
	if k == UDP {
		for _, s := range segs {
			if len(s.data) > 0 {
				st.add(Chunk{FromServer: s.server, Frame: s.frame, TS: s.ts, Data: s.data})
			}
		}
		return st, nil
	}
	if k == TLS || (k == HTTP && len(dec) > 0) {
		for _, ch := range dec {
			st.add(ch)
		}
		return st, nil
	}
	st.assembleTCP(segs)
	return st, nil
}

func endpoint(a dissect.Address, port uint32) string {
	if a.Type == dissect.AddrIPv6 {
		return fmt.Sprintf("[%s]:%d", a, port)
	}
	return fmt.Sprintf("%s:%d", a, port)
}

func (st *Stream) add(ch Chunk) {
	if ch.FromServer {
		st.ServerBytes += len(ch.Data)
	} else {
		st.ClientBytes += len(ch.Data)
	}
	st.Chunks = append(st.Chunks, ch)
}

// assembleTCP orders each direction by sequence number, drops
// retransmitted bytes and marks gaps, then interleaves by frame order.
func (st *Stream) assembleTCP(segs []seg) {
	type dirState struct {
		next    uint32
		started bool
		pending []seg
	}
	var dirs [2]dirState
	emit := func(s seg, missing int) {
		st.add(Chunk{FromServer: s.server, Frame: s.frame, TS: s.ts, Data: s.data, Missing: missing})
	}
	deliver := func(ds *dirState, s seg) bool {
		switch {
		case s.seq == ds.next:
			if len(s.data) > 0 {
				emit(s, 0)
			}
			ds.next += uint32(len(s.data))
			return true
		case int32(s.seq-ds.next) < 0:
			end := s.seq + uint32(len(s.data))
			if int32(end-ds.next) > 0 {
				cut := ds.next - s.seq
				s.data = s.data[cut:]
				emit(s, 0)
				ds.next = end
			}
			return true
		}
		return false
	}
	flush := func(ds *dirState) {
		for {
			progressed := false
			sort.Slice(ds.pending, func(i, j int) bool { return int32(ds.pending[i].seq-ds.pending[j].seq) < 0 })
			keep := ds.pending[:0]
			for _, p := range ds.pending {
				if !progressed && deliver(ds, p) {
					progressed = true
					continue
				}
				keep = append(keep, p)
			}
			ds.pending = keep
			if !progressed {
				return
			}
		}
	}
	for _, s := range segs {
		ds := &dirs[b2i(s.server)]
		if !ds.started {
			ds.next = s.seq
			if s.syn {
				ds.next++
			}
			ds.started = true
			if len(s.data) == 0 {
				continue
			}
		}
		if s.syn {
			continue
		}
		if len(s.data) == 0 {
			continue
		}
		if deliver(ds, s) {
			flush(ds)
		} else {
			ds.pending = append(ds.pending, s)
		}
	}
	// Whatever is still pending follows a gap in the capture.
	for i := range dirs {
		ds := &dirs[i]
		sort.Slice(ds.pending, func(a, b int) bool { return int32(ds.pending[a].seq-ds.pending[b].seq) < 0 })
		for _, p := range ds.pending {
			if int32(p.seq-ds.next) > 0 {
				missing := int(p.seq - ds.next)
				ds.next = p.seq
				emit(p, missing)
				ds.next += uint32(len(p.data))
				continue
			}
			deliver(ds, p)
		}
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
