package proto_test

import (
	"bytes"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/export"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func tlsCapture(t *testing.T, maxVersion uint16, mss int) []g.Packet {
	cert := g.SelfSigned(t, "example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}, MaxVersion: maxVersion}
	cli := &tls.Config{ServerName: "example.test", InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}, MaxVersion: maxVersion}
	writes, _ := g.TLSExchange(t, srv, cli, []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"), bytes.Repeat([]byte("x"), 3000))
	f := g.DefaultFlow()
	f.B.Port = 443
	return g.TLSCapture(f, writes, mss)
}

func TestTLS13(t *testing.T) {
	c := load(t, tlsCapture(t, tls.VersionTLS13, 1400))
	chello := matches(t, c, "tls.handshake.type == 1")
	if len(chello) != 1 {
		t.Fatalf("client hello frames: %v", chello)
	}
	cases := []struct {
		filter string
		want   int
	}{
		{`tls.handshake.extensions_server_name == "example.test"`, 1},
		{`tls.handshake.extensions_alpn_str == "h2"`, 1}, // the server's choice is encrypted in 1.3
		{"tls.handshake.extensions.supported_version == 0x0304", 2},
		{`tls.handshake.ja4 matches "^t13d[0-9]{4}h2_[0-9a-f]{12}_[0-9a-f]{12}$"`, 1},
		{`len(tls.handshake.ja3) == 32`, 1},
		{`tls.handshake.ja4s matches "^t130200_130[123]_[0-9a-f]{12}$"`, 1},
		{"tls.handshake.type == 2", 1},
		{"tls.record.opaque_type == 23", -1},
		{"tls.change_cipher_spec", -1},
	}
	for _, tc := range cases {
		got := matches(t, c, tc.filter)
		if (tc.want >= 0 && len(got) != tc.want) || (tc.want < 0 && len(got) == 0) {
			t.Errorf("%s: %v", tc.filter, got)
		}
	}
	w := c.Session().NewWorker(dissect.Options{Full: true, Columns: true})
	pi := w.Dissect(c.Input(chello[0]))
	if pi.Protocol() != "TLSv1.3" || pi.Info() != "Client Hello (SNI=example.test)" {
		t.Errorf("client hello columns: %q %q", pi.Protocol(), pi.Info())
	}
	sh := matches(t, c, "tls.handshake.type == 2")
	if pi := w.Dissect(c.Input(sh[0])); !strings.HasPrefix(pi.Info(), "Server Hello, Change Cipher Spec, Application Data") {
		t.Errorf("server hello info %q", pi.Info())
	}
}

func TestTLS12Certificate(t *testing.T) {
	// A small MSS forces records to span many TCP segments.
	c := load(t, tlsCapture(t, tls.VersionTLS12, 100))
	cases := []struct {
		filter string
		want   int
	}{
		{`x509ce.dNSName == "www.example.test"`, 1},
		{`x509af.subject.commonName == "example.test" && x509af.self_signed`, 1},
		{"tls.handshake.server_named_curve == 29 || tls.handshake.server_named_curve == 23", 1},
		{"tls.handshake.type == 14", 1},
		{"tls.handshake.type == 20", 0},
		{"tls.app_data", -1},
		{"tcp.segment.count > 5", -1},
	}
	for _, tc := range cases {
		got := matches(t, c, tc.filter)
		if (tc.want >= 0 && len(got) != tc.want) || (tc.want < 0 && len(got) == 0) {
			t.Errorf("%s: %v", tc.filter, got)
		}
	}
	w := c.Session().NewWorker(dissect.Options{Full: true, Columns: true})
	cert := matches(t, c, "tls.handshake.type == 11")
	var b bytes.Buffer
	pi := w.Dissect(c.Input(cert[0]))
	export.WriteTree(&b, &pi.Tree.Root)
	for _, want := range []string{"Certificate: ", "(CN=example.test,O=lazysniffer test)", "dNSName: www.example.test", "notAfter: "} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("certificate tree lacks %q", want)
		}
	}
	if !strings.Contains(pi.Info(), "Certificate") || pi.Protocol() != "TLSv1.2" {
		t.Errorf("columns %q %q", pi.Protocol(), pi.Info())
	}
	fin := matches(t, c, `tls.record.content_type == 22 && tls.handshake.data`)
	if len(fin) == 0 {
		t.Errorf("encrypted Finished not shown as encrypted handshake")
	}
}
