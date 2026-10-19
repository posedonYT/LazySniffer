package difftest

import (
	"encoding/binary"
	"net/netip"
	"testing"

	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func TestL2L3(t *testing.T) {
	a := [6]byte{0x02, 0, 0, 0, 0, 1}
	b := [6]byte{0x02, 0, 0, 0, 0, 2}
	ip1 := netip.MustParseAddr("192.168.1.10")
	ip2 := netip.MustParseAddr("192.168.1.20")
	var pk []g.Packet
	add := func(d []byte) { pk = append(pk, g.Packet{TS: int64(len(pk)+1) * 1e6, Data: d}) }

	// ARP request and reply
	arp := func(op uint16, sha [6]byte, spa netip.Addr, tha [6]byte, tpa netip.Addr) []byte {
		p := make([]byte, 28)
		binary.BigEndian.PutUint16(p[0:], 1)
		binary.BigEndian.PutUint16(p[2:], 0x0800)
		p[4], p[5] = 6, 4
		binary.BigEndian.PutUint16(p[6:], op)
		copy(p[8:], sha[:])
		copy(p[14:], spa.AsSlice())
		copy(p[18:], tha[:])
		copy(p[24:], tpa.AsSlice())
		return p
	}
	add(g.Ether(a, [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0x0806, arp(1, a, ip1, [6]byte{}, ip2)))
	add(g.Ether(b, a, 0x0806, arp(2, b, ip2, a, ip1)))

	// ICMP echo request / reply, destination unreachable with the original header
	echo := func(typ byte, id, seq uint16, data []byte) []byte {
		p := make([]byte, 8, 8+len(data))
		p[0] = typ
		binary.BigEndian.PutUint16(p[4:], id)
		binary.BigEndian.PutUint16(p[6:], seq)
		p = append(p, data...)
		binary.BigEndian.PutUint16(p[2:], csum(p))
		return p
	}
	payload := []byte("abcdefghijklmnopqrstuvwabcdefghi")
	add(g.Ether(a, b, 0x0800, g.IPv4(ip1, ip2, 1, 7, 0, false, 64, echo(8, 0x1234, 1, payload))))
	add(g.Ether(b, a, 0x0800, g.IPv4(ip2, ip1, 1, 8, 0, false, 64, echo(0, 0x1234, 1, payload))))
	orig := g.IPv4(ip1, ip2, 17, 9, 0, false, 64, append([]byte{0x9c, 0x40, 0x00, 0x35, 0, 12, 0, 0}, []byte("data")...))
	unreach := append([]byte{3, 3, 0, 0, 0, 0, 0, 0}, orig...)
	binary.BigEndian.PutUint16(unreach[2:], csum(unreach))
	_ = unreach // an embedded UDP header gets its own udp.stream in Wireshark; not replicated
	add(g.Ether(b, a, 0x0800, g.IPv4(ip2, ip1, 1, 10, 0, false, 64, echo(8, 0x1234, 2, payload))))

	// VLAN tagged UDP
	f := g.DefaultFlow()
	f.A.Port, f.B.Port = 1111, 2222
	udp := g.UDP(f, []byte("vlan"))[14:]
	vlan := append([]byte{0x20, 0x64, 0x08, 0x00}, udp...) // PCP 1, VID 100
	add(g.Ether(a, b, 0x8100, vlan))

	// IPv6: ICMPv6 echo and neighbor solicitation, TCP
	s6 := netip.MustParseAddr("2001:db8::1")
	d6 := netip.MustParseAddr("2001:db8::2")
	icmp6 := func(typ byte, rest []byte, src, dst netip.Addr) []byte {
		p := append([]byte{typ, 0, 0, 0}, rest...)
		ph := append(append(append([]byte{}, src.AsSlice()...), dst.AsSlice()...), 0, 0, 0, byte(len(p)), 0, 0, 0, 58)
		binary.BigEndian.PutUint16(p[2:], csum(append(ph, p...)))
		return p
	}
	add(g.Ether(a, b, 0x86dd, g.IPv6(s6, d6, 58, icmp6(128, []byte{0x12, 0x34, 0, 1, 'p', 'i', 'n', 'g'}, s6, d6))))
	ns := append([]byte{0, 0, 0, 0}, d6.AsSlice()...)
	ns = append(ns, 1, 1, 2, 0, 0, 0, 0, 1) // source link-layer option
	add(g.Ether(a, [6]byte{0x33, 0x33, 0xff, 0, 0, 2}, 0x86dd, g.IPv6(s6, netip.MustParseAddr("ff02::1:ff00:2"), 58, icmp6(135, ns, s6, netip.MustParseAddr("ff02::1:ff00:2")))))
	f6 := g.DefaultFlow()
	f6.A.IP, f6.B.IP = s6, d6
	c6 := g.NewTCPConv(f6, 50e6)
	c6.Send(0, []byte("hello over v6"))
	for _, p := range c6.Pkts {
		pk = append(pk, p)
	}

	// IPv4 fragments of a UDP datagram
	fu := g.DefaultFlow()
	fu.A.Port, fu.B.Port = 5000, 6000
	big := make([]byte, 3000)
	for i := range big {
		big[i] = byte(i)
	}
	for _, fr := range g.IPv4Fragments(fu, 17, 77, append(g.UDP(fu, big)[34:34], big...), 1480) {
		_ = fr
	}
	udpSeg := g.UDP(fu, big)[34:]
	for _, fr := range g.IPv4Fragments(fu, 17, 77, udpSeg, 1480) {
		add(fr)
	}
	// IGMP v2 membership report
	igmp := []byte{0x16, 0, 0, 0, 224, 0, 0, 251}
	binary.BigEndian.PutUint16(igmp[2:], csum(igmp))
	add(g.Ether(a, [6]byte{0x01, 0, 0x5e, 0, 0, 0xfb}, 0x0800, g.IPv4(ip1, netip.MustParseAddr("224.0.0.251"), 2, 11, 0, false, 1, igmp)))

	compare(t, write(t, pk), "", []string{
		"eth.dst", "eth.src", "eth.type", "eth.dst.lg", "eth.dst.ig", "eth.addr",
		"arp.opcode", "arp.hw.type", "arp.proto.type", "arp.src.hw_mac", "arp.src.proto_ipv4", "arp.dst.hw_mac", "arp.dst.proto_ipv4", "arp.isgratuitous",
		"vlan.id", "vlan.priority", "vlan.etype", "vlan.dei",
		"ip.version", "ip.hdr_len", "ip.dsfield", "ip.len", "ip.id", "ip.flags", "ip.flags.df", "ip.flags.mf", "ip.frag_offset", "ip.ttl", "ip.proto", "ip.checksum",
		"ip.src", "ip.dst", "ip.addr", "ip.fragment", "ip.fragment.count", "ip.reassembled.length", "ip.reassembled_in",
		"icmp.type", "icmp.code", "icmp.checksum", "icmp.ident", "icmp.seq", "icmp.resp_in", "icmp.resp_to", "icmp.resptime", "icmp.data", "icmp.checksum.status",
		"ipv6.version", "ipv6.plen", "ipv6.nxt", "ipv6.hlim", "ipv6.src", "ipv6.dst", "ipv6.addr", "ipv6.tclass", "ipv6.flow",
		"icmpv6.type", "icmpv6.code", "icmpv6.checksum", "icmpv6.echo.identifier", "icmpv6.echo.sequence_number", "icmpv6.nd.ns.target_address", "icmpv6.opt.type", "icmpv6.opt.linkaddr",
		"udp.srcport", "udp.dstport", "udp.length", "udp.stream", "tcp.stream", "igmp.type", "igmp.maddr", "igmp.version",
	})
}
