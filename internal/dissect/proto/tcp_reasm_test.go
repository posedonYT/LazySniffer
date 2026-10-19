package proto_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	d "github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/dissect/proto"
	"github.com/poseydon/lazysniffer/internal/export"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

// A toy protocol on TCP port 7777: 2-byte length, then a message.
var (
	toyProto = d.RegisterProto("Toy length-prefixed protocol", "TOY", "toy")
	hfToyLen = toyProto.Field("toy.len", "Length", d.FtUint16)
	hfToyMsg = toyProto.Field("toy.msg", "Message", d.FtString)
)

func init() {
	proto.TCPPortTable.Add(7777, d.NewHandle(toyProto, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		return proto.TCPDissectPDUs(tvb, pi, tree, 2, func(tvb *d.Tvb, off int) int {
			return 2 + int(tvb.U16(off))
		}, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
			pi.SetProtocol("TOY")
			tt := tree.AddProtocol(toyProto, tvb, 0, -1)
			tt.AddUint(hfToyLen, tvb, 0, 2)
			_, msg := tt.AddString(hfToyMsg, tvb, 2, tvb.Len()-2)
			pi.AppendInfoSep(", ", "msg="+msg)
			return tvb.Len()
		})
	}))
}

func toy(msgs ...string) []byte {
	var b []byte
	for _, m := range msgs {
		b = binary.BigEndian.AppendUint16(b, uint16(len(m)))
		b = append(b, m...)
	}
	return b
}

func TestTCPReassembly(t *testing.T) {
	f := g.DefaultFlow()
	f.B.Port = 7777
	r := f.Rev()
	stream := toy("hello", strings.Repeat("A", 3000), "x", "yy", "zzz")
	// Segment boundaries split headers and bodies in awkward places.
	cuts := []int{1, 200, 1500, 3006, 3011, len(stream)}
	var pkts []g.Packet
	ts := int64(1e9)
	add := func(b []byte) { ts += 1e6; pkts = append(pkts, g.Packet{TS: ts, Data: b}) }
	add(g.TCP(f, 100, 0, g.SYN, 65535, nil, nil))
	add(g.TCP(r, 900, 101, g.SYN|g.ACK, 65535, nil, nil))
	add(g.TCP(f, 101, 901, g.ACK, 65535, nil, nil))
	prev := 0
	seq := uint32(101)
	for _, c := range cuts {
		add(g.TCP(f, seq, 901, g.ACK|g.PSH, 65535, nil, stream[prev:c]))
		seq += uint32(c - prev)
		prev = c
	}
	// A retransmission of the second data segment (well after the iRTT, so
	// not out-of-order) must not break anything.
	ts += 50e6
	add(g.TCP(f, 102, 901, g.ACK, 65535, nil, stream[1:200]))
	c := load(t, pkts)
	// Frames: 4..9 data, 10 retransmission. PDUs: hello 0-6, A×3000 7-3008,
	// x 3009-3011, yy 3012-3015, zzz 3016-3020; segments end at 1, 200,
	// 1500, 3006, 3011 and 3021.
	cases := []struct {
		filter string
		want   []uint32
	}{
		{`toy.msg == "hello"`, []uint32{5}},
		{`len(toy.msg) == 3000`, []uint32{8}},
		{`toy.msg == "x" && toy.msg == "yy" && toy.msg == "zzz"`, []uint32{9}},
		{"tcp.reassembled_in == 5", []uint32{4}},
		{"tcp.reassembled_in == 8", []uint32{5, 6, 7}},
		{"tcp.reassembled_in == 9", []uint32{8}},
		{"tcp.segment.count == 4 && tcp.reassembled.length == 3004", []uint32{8}},
		{"toy", []uint32{5, 8, 9}},
		{"tcp.analysis.retransmission", []uint32{10}},
	}
	for _, tc := range cases {
		if got := matches(t, c, tc.filter); !eq(got, tc.want...) {
			t.Errorf("%s: got %v, want %v", tc.filter, got, tc.want)
		}
	}
	w := c.Session().NewWorker(d.Options{Full: true, Columns: true})
	pi := w.Dissect(c.Input(6))
	if !strings.Contains(pi.Info(), "[TCP PDU reassembled in") {
		t.Errorf("frame 6 info %q", pi.Info())
	}
	var b bytes.Buffer
	export.WriteTree(&b, &w.Dissect(c.Input(8)).Tree.Root)
	if !strings.Contains(b.String(), "[4 Reassembled TCP Segments (3004 bytes): #5(193), #6(1300), #7(1506), #8(5)]") {
		t.Errorf("frame 8 tree:\n%s", b.String())
	}
	if pi := w.Dissect(c.Input(10)); !strings.Contains(pi.Info(), "[TCP Retransmission]") {
		t.Errorf("frame 10: %q", pi.Info())
	}
}
