package proto_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/poseydon/lazysniffer/internal/decrypt"
	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/export"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func TestQUICInitial(t *testing.T) {
	ch := g.QUICClientHello(t, "quic.example.test")
	if len(ch) == 0 {
		t.Fatal("no client hello")
	}
	f := g.DefaultFlow()
	f.B.Port = 443
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x01, 0x02, 0x03, 0x04}
	// Split the ClientHello over two Initial packets, second one first (reordered).
	half := len(ch) / 2
	p1 := g.QUICInitial(t, 1, dcid, scid, 0, 0, ch[:half], true)
	p2 := g.QUICInitial(t, 1, dcid, scid, 1, uint64(half), ch[half:], true)
	pkts := []g.Packet{
		{TS: 1e9, Data: g.UDP(f, p1)},
		{TS: 2e9, Data: g.UDP(f, p2)},
	}
	c := load(t, pkts)
	for filter, want := range map[string]int{
		"quic":                                 2,
		"quic.long.packet_type == 0":           2,
		`quic.dcid == 83:94:c8:f0:3e:51:57:08`: 2,
		"tls.handshake.type == 1":              1,
		`tls.handshake.extensions_server_name == "quic.example.test"`: 1,
		`tls.handshake.ja4 matches "^q13d"`:                           1,
		"quic.packet_number == 1":                                     1,
	} {
		if got := len(matches(t, c, filter)); got != want {
			t.Errorf("%s: %d frames, want %d", filter, got, want)
		}
	}
	_ = decrypt.QUICv1
}

func TestQUICTree(t *testing.T) {
	ch := g.QUICClientHello(t, "quic.example.test")
	f := g.DefaultFlow()
	f.B.Port = 443
	p := g.QUICInitial(t, 1, []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9}, 0, 0, ch, true)
	c := load(t, []g.Packet{{TS: 1e9, Data: g.UDP(f, p)}})
	w := c.Session().NewWorker(dissect.Options{Full: true, Columns: true})
	pi := w.Dissect(c.Input(1))
	var b bytes.Buffer
	export.WriteTree(&b, &pi.Tree.Root)
	for _, want := range []string{"QUIC IETF: Initial", "CRYPTO", "Parameter: initial_max_data", "quic.example.test"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("tree lacks %q", want)
		}
	}
	if pi.Protocol() != "QUIC" || !strings.Contains(pi.Info(), "Initial, DCID=0102030405060708") {
		t.Errorf("columns %q %q", pi.Protocol(), pi.Info())
	}
	if testing.Verbose() {
		t.Log(b.String(), pi.Info())
	}
}
