package proto_test

import (
	"encoding/binary"
	"net/netip"
	"testing"

	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func TestTunnels(t *testing.T) {
	f := g.DefaultFlow()
	inner := g.TCP(g.DefaultFlow(), 1, 0, g.SYN, 1000, nil, nil) // Ethernet frame
	innerIP := inner[14:]

	// VXLAN: UDP/4789 carrying the inner Ethernet frame.
	vf := f
	vf.B.Port = 4789
	vx := append([]byte{0x08, 0, 0, 0, 0, 0, 42, 0}, inner...)
	vxlan := g.UDP(vf, vx)

	// GRE carrying IPv4.
	gre := g.Ether(f.A.MAC, f.B.MAC, 0x0800, g.IPv4(f.A.IP, f.B.IP, 47, 1, 0, false, 64, append([]byte{0, 0, 0x08, 0}, innerIP...)))

	// MPLS label 100 then IPv4.
	lbl := make([]byte, 4)
	binary.BigEndian.PutUint32(lbl, 100<<12|1<<8|64)
	mpls := g.Ether(f.A.MAC, f.B.MAC, 0x8847, append(lbl, innerIP...))

	// PPPoE session carrying IPv4.
	ppp := []byte{0x11, 0x00, 0x12, 0x34, 0, 0, 0x00, 0x21}
	binary.BigEndian.PutUint16(ppp[4:], uint16(2+len(innerIP)))
	pppoe := g.Ether(f.A.MAC, f.B.MAC, 0x8864, append(ppp, innerIP...))

	// IGMPv2 report for 239.1.2.3.
	igmpMsg := []byte{0x16, 0, 0, 0, 239, 1, 2, 3}
	binary.BigEndian.PutUint16(igmpMsg[2:], inet(igmpMsg))
	igmp := g.Ether(f.A.MAC, [6]byte{1, 0, 0x5e, 1, 2, 3}, 0x0800, g.IPv4(f.A.IP, netip.MustParseAddr("239.1.2.3"), 2, 9, 0, false, 1, igmpMsg))

	// SCTP INIT + ABORT.
	sctp := []byte{0x0b, 0x59, 0x0b, 0x59, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 0, 0, 20, 0xde, 0xad, 0xbe, 0xef, 0, 1, 0, 0, 0, 10, 0, 10, 0, 0, 0, 1,
		6, 0, 0, 4}
	sctpPkt := g.Ether(f.A.MAC, f.B.MAC, 0x0800, g.IPv4(f.A.IP, f.B.IP, 132, 3, 0, false, 64, sctp))

	c := load(t, []g.Packet{{TS: 1e6, Data: vxlan}, {TS: 2e6, Data: gre}, {TS: 3e6, Data: mpls}, {TS: 4e6, Data: pppoe}, {TS: 5e6, Data: igmp}, {TS: 6e6, Data: sctpPkt}})
	cases := []struct {
		filter string
		want   []uint32
	}{
		{"vxlan.vni == 42 && tcp.flags.syn == 1 && ip.src#2 == 10.0.0.1", []uint32{1}},
		{"gre && tcp", []uint32{2}},
		{"mpls.label == 100 && mpls.bottom && tcp", []uint32{3}},
		{"pppoes && ppp.protocol == 0x0021 && pppoe.session_id == 0x1234 && tcp", []uint32{4}},
		{"igmp.type == 0x16 && igmp.maddr == 239.1.2.3 && igmp.checksum.status == 1", []uint32{5}},
		{"sctp.chunk_type == INIT && sctp.chunk_type eq ABORT && sctp.init_initiate_tag == 0xdeadbeef", []uint32{6}},
		{"tcp", []uint32{1, 2, 3, 4}},
	}
	for _, tc := range cases {
		if got := matches(t, c, tc.filter); !eq(got, tc.want...) {
			t.Errorf("%s: got %v, want %v", tc.filter, got, tc.want)
		}
	}
}

func inet(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}
