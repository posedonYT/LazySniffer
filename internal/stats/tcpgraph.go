package stats

import (
	"context"
	"fmt"

	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/store"
)

// TCPPoint is one TCP segment of a stream.
type TCPPoint struct {
	Frame    uint32
	T        float64 // seconds since the first frame of the stream
	Seq      float64 // relative sequence number of the first byte
	NxtSeq   float64
	Ack      float64
	Len      float64
	Win      float64 // calculated window size
	RTT      float64 // ack_rtt in seconds, -1 if none
	InFlight float64 // bytes in flight, -1 if unknown
}

// TCPStream holds the segments of both directions (index 0: client→server).
type TCPStream struct {
	Index  uint32
	Client string
	Server string
	Dir    [2][]TCPPoint
	Span   float64 // seconds
}

// TCPGraphData extracts the per-segment values needed by the TCP stream graphs.
func TCPGraphData(ctx context.Context, c *store.Capture, stream uint32) (*TCPStream, error) {
	flt, err := dfilter.Compile(fmt.Sprintf("tcp.stream eq %d", stream))
	if err != nil {
		return nil, err
	}
	frames, err := engine.Filter(ctx, c, flt, 1, uint32(c.Count()), nil)
	if err != nil {
		return nil, err
	}
	if len(frames) == 0 {
		return nil, fmt.Errorf("no TCP stream %d", stream)
	}
	names := []string{"tcp.seq", "tcp.nxtseq", "tcp.ack", "tcp.len", "tcp.window_size", "tcp.analysis.ack_rtt", "tcp.analysis.bytes_in_flight"}
	fd := make([]*dissect.FieldDef, len(names))
	want := make([]bool, dissect.NumFields())
	for i, n := range names {
		fd[i] = dissect.LookupField(n)
		if fd[i] != nil {
			want[fd[i].ID] = true
		}
	}
	w := c.Session().NewWorker(dissect.Options{Want: want})
	st := &TCPStream{Index: stream}
	t0 := c.Frame(frames[0]).TS
	for _, num := range frames {
		pi := w.Dissect(c.Input(num))
		if pi.Conv == nil {
			continue
		}
		if st.Client == "" {
			st.Client = fmt.Sprintf("%s:%d", pi.Conv.AddrA, pi.Conv.PortA)
			st.Server = fmt.Sprintf("%s:%d", pi.Conv.AddrB, pi.Conv.PortB)
		}
		dir := 0
		if !pi.Conv.FromA(pi.Src, pi.SrcPort) {
			dir = 1
		}
		get := func(i int, def float64) float64 {
			if fd[i] == nil {
				return def
			}
			v, ok := pi.Tree.First(fd[i])
			if !ok {
				return def
			}
			if v.V.T == dissect.FtRelTime {
				return float64(int64(v.V.U)) / 1e9
			}
			return float64(v.V.U)
		}
		p := TCPPoint{Frame: num, T: float64(pi.TS-t0) / 1e9, Seq: get(0, 0), NxtSeq: get(1, 0), Ack: get(2, 0), Len: get(3, 0),
			Win: get(4, 0), RTT: get(5, -1), InFlight: get(6, -1)}
		st.Dir[dir] = append(st.Dir[dir], p)
		st.Span = p.T
	}
	return st, nil
}
