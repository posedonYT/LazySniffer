package proto_test

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/export"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func TestIPv4Defragment(t *testing.T) {
	f := g.DefaultFlow()
	f.B.Port = 9999
	payload := bytes.Repeat([]byte("0123456789"), 300) // 3000 bytes
	dgram := g.UDPDatagram(f, payload)
	frags := g.IPv4Fragments(f, 17, 0x1c46, dgram, 1480)
	// Deliver out of order with an unrelated packet in between.
	other := g.UDP(f.Rev(), []byte("hello"))
	var pkts []g.Packet
	for i, b := range [][]byte{frags[1], other, frags[0], frags[2]} {
		pkts = append(pkts, g.Packet{TS: int64(i+1) * 1e6, Data: b})
	}
	c := load(t, pkts)
	if got := matches(t, c, "udp.length == 3008"); !eq(got, 4) {
		t.Errorf("reassembled UDP should be dissected in frame 4, got %v", got)
	}
	if got := matches(t, c, "ip.reassembled_in == 4"); !eq(got, 1, 3) {
		t.Errorf("ip.reassembled_in: %v", got)
	}
	if got := matches(t, c, "ip.fragment.count == 3 && ip.reassembled.length == 3008"); !eq(got, 4) {
		t.Errorf("fragment tree: %v", got)
	}
	if got := matches(t, c, `udp.payload contains "89012345"`); !eq(got, 4) {
		t.Errorf("payload search across fragments: %v", got)
	}
	w := c.Session().NewWorker(dissect.Options{Full: true, Columns: true})
	pi := w.Dissect(c.Input(1))
	if !strings.Contains(pi.Info(), "Fragmented IP protocol (proto=UDP 17, off=1480, ID=1c46) [Reassembled in #4]") {
		t.Errorf("frame 1 info: %q", pi.Info())
	}
	pi = w.Dissect(c.Input(4))
	if len(pi.Sources) != 2 || pi.Sources[1].Name != "Reassembled IPv4" || len(pi.Sources[1].Data) != 3008 {
		t.Fatalf("sources: %+v", pi.Sources)
	}
	var b bytes.Buffer
	export.WriteTree(&b, &pi.Tree.Root)
	if !strings.Contains(b.String(), "[3 IPv4 Fragments (3008 bytes): #3(1480), #1(1480), #4(48)]") {
		t.Errorf("tree:\n%s", b.String())
	}
}

func TestIPv6Defragment(t *testing.T) {
	f := g.DefaultFlow()
	f.A.IP = netip.MustParseAddr("2001:db8::1")
	f.B.IP = netip.MustParseAddr("2001:db8::2")
	f.B.Port = 9999
	dgram := g.UDPDatagram(f, bytes.Repeat([]byte{7}, 2000))
	frags := g.IPv6Fragments(f, 17, 0xabcdef, dgram, 1200)
	c := load(t, []g.Packet{{TS: 1e6, Data: frags[0]}, {TS: 2e6, Data: frags[1]}})
	if got := matches(t, c, "udp.length == 2008 && ipv6.fragment.count == 2"); !eq(got, 2) {
		t.Errorf("IPv6 reassembly: %v", got)
	}
	if got := matches(t, c, "ipv6.reassembled_in == 2"); !eq(got, 1) {
		t.Errorf("ipv6.reassembled_in: %v", got)
	}
}
