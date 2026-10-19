package proto_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/dissect"
	_ "github.com/poseydon/lazysniffer/internal/dissect/proto"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/export"
	"github.com/poseydon/lazysniffer/internal/store"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

const ms = int64(1e6)

func load(t *testing.T, pkts []g.Packet) *store.Capture {
	t.Helper()
	c, err := store.Open(g.WritePcapng(t, pkts))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Load(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	return c
}

func matches(t *testing.T, c *store.Capture, filter string) []uint32 {
	t.Helper()
	f, err := dfilter.Compile(filter)
	if err != nil {
		t.Fatalf("%s: %v", filter, err)
	}
	got, err := engine.Filter(context.Background(), c, f, 1, uint32(c.Count()), nil)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func eq(a []uint32, b ...uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func data(n int) []byte { return bytes.Repeat([]byte{'x'}, n) }

func TestTCPAnalysis(t *testing.T) {
	f := g.DefaultFlow()
	r := f.Rev()
	ts := int64(1_700_000_000_000_000_000)
	at := func(off int64, b []byte) g.Packet { return g.Packet{TS: ts + off, Data: b} }
	pkts := []g.Packet{
		at(0, g.TCP(f, 1000, 0, g.SYN, 65535, g.SynOpts(1460, 7), nil)),              // 1
		at(10*ms, g.TCP(r, 5000, 1001, g.SYN|g.ACK, 65535, g.SynOpts(1460, 7), nil)), // 2
		at(20*ms, g.TCP(f, 1001, 5001, g.ACK, 512, nil, nil)),                        // 3 iRTT = 20ms
		at(21*ms, g.TCP(f, 1001, 5001, g.PSH|g.ACK, 512, nil, data(100))),            // 4
		at(22*ms, g.TCP(f, 1101, 5001, g.ACK, 512, nil, data(100))),                  // 5
		at(40*ms, g.TCP(r, 5001, 1101, g.ACK, 512, nil, nil)),                        // 6 acks 4
		at(300*ms, g.TCP(f, 1101, 5001, g.ACK, 512, nil, data(100))),                 // 7 retransmission of 5
		at(310*ms, g.TCP(r, 5001, 1101, g.ACK, 512, nil, nil)),                       // 8 dup ack 6#1
		at(311*ms, g.TCP(r, 5001, 1101, g.ACK, 512, nil, nil)),                       // 9 dup ack 6#2
		at(312*ms, g.TCP(f, 1101, 5001, g.ACK, 512, nil, data(100))),                 // 10 fast retransmission
		at(320*ms, g.TCP(f, 1301, 5001, g.ACK, 512, nil, data(100))),                 // 11 previous segment not captured
		at(321*ms, g.TCP(f, 1201, 5001, g.ACK, 512, nil, data(100))),                 // 12 out of order
		at(330*ms, g.TCP(r, 5001, 1401, g.ACK, 0, nil, nil)),                         // 13 zero window
		at(500*ms, g.TCP(f, 1401, 5001, g.ACK, 512, nil, data(1))),                   // 14 zero window probe
		at(510*ms, g.TCP(r, 5001, 1401, g.ACK, 0, nil, nil)),                         // 15 zero window probe ack
		at(520*ms, g.TCP(r, 5001, 1401, g.ACK, 512, nil, nil)),                       // 16 window update
		at(900*ms, g.TCP(f, 1400, 5001, g.ACK, 512, nil, nil)),                       // 17 keep-alive
		at(910*ms, g.TCP(r, 5001, 1401, g.ACK, 512, nil, nil)),                       // 18 keep-alive ack
		at(920*ms, g.TCP(f, 1001, 5001, g.ACK, 512, nil, data(100))),                 // 19 spurious retransmission
		at(930*ms, g.TCP(f, 1401, 5001, g.FIN|g.ACK, 512, nil, nil)),                 // 20
		at(940*ms, g.TCP(r, 5001, 1402, g.FIN|g.ACK, 512, nil, nil)),                 // 21
		at(950*ms, g.TCP(f, 1402, 5002, g.ACK, 512, nil, nil)),                       // 22
	}
	c := load(t, pkts)
	cases := []struct {
		filter string
		want   []uint32
	}{
		{"tcp.analysis.retransmission", []uint32{7}},
		{"tcp.analysis.duplicate_ack", []uint32{8, 9}},
		{"tcp.analysis.duplicate_ack_frame == 6", []uint32{8, 9}},
		{"tcp.analysis.duplicate_ack_num == 2", []uint32{9}},
		{"tcp.analysis.fast_retransmission", []uint32{10}},
		{"tcp.analysis.lost_segment", []uint32{11}},
		{"tcp.analysis.out_of_order", []uint32{12}},
		{"tcp.analysis.zero_window", []uint32{13, 15}},
		{"tcp.analysis.zero_window_probe", []uint32{14}},
		{"tcp.analysis.zero_window_probe_ack", []uint32{15}},
		{"tcp.analysis.window_update", []uint32{16}},
		{"tcp.analysis.keep_alive", []uint32{17}},
		{"tcp.analysis.keep_alive_ack", []uint32{18}},
		{"tcp.analysis.spurious_retransmission", []uint32{19}},
		{"tcp.analysis.acks_frame == 4", []uint32{6}},
		{"tcp.analysis.initial_rtt == 0.02", []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}},
		{"tcp.completeness == 31", []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}},
		{"tcp.analysis.rto_frame == 5", []uint32{7, 10}},
		{"tcp.window_size == 65536", []uint32{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 16, 17, 18, 19, 20, 21, 22}},
	}
	for _, tc := range cases {
		if got := matches(t, c, tc.filter); !eq(got, tc.want...) {
			t.Errorf("%s: got %v, want %v", tc.filter, got, tc.want)
		}
	}
	// Info column tags.
	w := c.Session().NewWorker(dissect.Options{Full: true, Columns: true})
	info := func(n uint32) string { return w.Dissect(c.Input(n)).Info() }
	for n, want := range map[uint32]string{7: "[TCP Retransmission] ", 8: "[TCP Dup ACK 6#1] ", 13: "[TCP ZeroWindow] ", 11: "[TCP Previous segment not captured] "} {
		if s := info(n); len(s) < len(want) || s[:len(want)] != want {
			t.Errorf("frame %d info %q, want prefix %q", n, s, want)
		}
	}
	var b bytes.Buffer
	export.WriteTree(&b, &w.Dissect(c.Input(7)).Tree.Root)
	if !bytes.Contains(b.Bytes(), []byte("This frame is a (suspected) retransmission")) || !bytes.Contains(b.Bytes(), []byte("[Conversation completeness: Complete, WITH_DATA (31)]")) {
		t.Errorf("tree:\n%s", b.String())
	}
}
