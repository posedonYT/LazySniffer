package proto_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/export"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

type dnsMsg struct{ b []byte }

func (m *dnsMsg) u16(v int) *dnsMsg     { m.b = binary.BigEndian.AppendUint16(m.b, uint16(v)); return m }
func (m *dnsMsg) u32(v int) *dnsMsg     { m.b = binary.BigEndian.AppendUint32(m.b, uint32(v)); return m }
func (m *dnsMsg) raw(b ...byte) *dnsMsg { m.b = append(m.b, b...); return m }
func (m *dnsMsg) name(n string) *dnsMsg {
	for _, l := range strings.Split(n, ".") {
		m.b = append(append(m.b, byte(len(l))), l...)
	}
	m.b = append(m.b, 0)
	return m
}

func TestDNS(t *testing.T) {
	f := g.DefaultFlow()
	f.B.Port = 53
	q := (&dnsMsg{}).u16(0x1234).u16(0x0100).u16(1).u16(0).u16(0).u16(1).
		name("www.example.com").u16(65).u16(1).
		raw(0).u16(41).u16(1232).u32(0).u16(11).u16(8).u16(7).u16(1).raw(24, 0, 192, 0, 2)
	r := (&dnsMsg{}).u16(0x1234).u16(0x8180).u16(1).u16(3).u16(1).u16(0).
		name("www.example.com").u16(65).u16(1).
		raw(0xc0, 12).u16(5).u16(1).u32(300).u16(6).raw(3, 'c', 'd', 'n', 0xc0, 16). // www.example.com CNAME cdn.example.com
		raw(0xc0, 45).u16(1).u16(1).u32(60).u16(4).raw(93, 184, 216, 34)             // cdn.example.com A
	// HTTPS 1 . alpn=h2,h3 ech=...
	https := (&dnsMsg{}).u16(1).raw(0).
		u16(1).u16(6).raw(2, 'h', '2', 2, 'h', '3').
		u16(5).u16(4).raw(0xfe, 0x0d, 0, 0)
	r.raw(0xc0, 45).u16(65).u16(1).u32(60).u16(len(https.b)).raw(https.b...)
	soa := (&dnsMsg{}).name("ns.example.com").name("admin.example.com").u32(2024).u32(7200).u32(900).u32(1209600).u32(86400)
	r.raw(0xc0, 16).u16(6).u16(1).u32(3600).u16(len(soa.b)).raw(soa.b...)
	c := load(t, []g.Packet{{TS: 1e9, Data: g.UDP(f, q.b)}, {TS: 1e9 + 25e6, Data: g.UDP(f.Rev(), r.b)}})
	cases := []struct {
		filter string
		want   []uint32
	}{
		{`dns.qry.name == "www.example.com" && dns.qry.type == 65`, []uint32{1, 2}},
		{"dns.opt.client.netmask == 24 && dns.opt.client.addr4 == 192.0.2.0", []uint32{1}},
		{`dns.cname == "cdn.example.com" && dns.a == 93.184.216.34`, []uint32{2}},
		{`dns.svcb.svcparam.alpn.identifier == "h3" && dns.svcb.svcparam.ech`, []uint32{2}},
		{`dns.soa.mname == "ns.example.com" && dns.soa.serial_number == 2024`, []uint32{2}},
		{"dns.response_in == 2", []uint32{1}},
		{"dns.time == 0.025 && dns.response_to == 1", []uint32{2}},
		{"dns.flags.response == 1 && dns.flags.rcode == 0", []uint32{2}},
		{"dns.count.answers == 3", []uint32{2}},
	}
	for _, tc := range cases {
		if got := matches(t, c, tc.filter); !eq(got, tc.want...) {
			t.Errorf("%s: got %v, want %v", tc.filter, got, tc.want)
		}
	}
	w := c.Session().NewWorker(dissect.Options{Full: true, Columns: true})
	want := "Standard query response 0x1234 HTTPS www.example.com CNAME cdn.example.com A 93.184.216.34 HTTPS"
	if pi := w.Dissect(c.Input(2)); !strings.HasPrefix(pi.Info(), want) {
		t.Errorf("info %q\nwant %q", pi.Info(), want)
	}
	var b bytes.Buffer
	export.WriteTree(&b, &w.Dissect(c.Input(2)).Tree.Root)
	if !strings.Contains(b.String(), "cdn.example.com: type HTTPS, class IN, priority 1, target <Root>, alpn=h2,h3 ech") {
		t.Errorf("tree:\n%s", b.String())
	}
}
