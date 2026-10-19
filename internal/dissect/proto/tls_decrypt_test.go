package proto_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/poseydon/lazysniffer/internal/keylog"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func decryptedCapture(t *testing.T, version uint16, suites []uint16) []g.Packet {
	cert := g.SelfSigned(t, "example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}, MinVersion: version, MaxVersion: version, CipherSuites: suites}
	cli := &tls.Config{ServerName: "example.test", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}, MinVersion: version, MaxVersion: version, CipherSuites: suites}
	body := bytes.Repeat([]byte("JPEGDATA"), 5000) // 40000 bytes: several records
	resp := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
	writes, kl := g.TLSExchange(t, srv, cli, []byte("GET /pic.jpg HTTP/1.1\r\nHost: example.test\r\n\r\n"), resp)
	useKeys(t, kl)
	f := g.DefaultFlow()
	f.B.Port = 443
	return g.TLSCapture(f, writes, 1400)
}

func TestTLSDecrypt(t *testing.T) {
	cases := []struct {
		name    string
		version uint16
		suites  []uint16
	}{
		{"1.3", tls.VersionTLS13, nil},
		{"1.2-gcm", tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}},
		{"1.2-chacha", tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}},
		{"1.2-cbc", tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := load(t, decryptedCapture(t, tc.version, tc.suites))
			for filter, want := range map[string]int{
				`http.request.method == "GET"`:                                   1,
				`http.request.method == "GET" && http.request.uri == "/pic.jpg"`: 1,
				`http.response.code == 200`:                                      1,
				`http.content_type == "image/jpeg"`:                              1,
				`http.content_length == 40000`:                                   1,
				"tls.handshake.type == 20":                                       -1, // Finished is decrypted
				`media.type == "image/jpeg"`:                                     1,
			} {
				got := matches(t, c, filter)
				if (want >= 0 && len(got) != want) || (want < 0 && len(got) == 0) {
					t.Errorf("%s: %v", filter, got)
				}
			}
		})
	}
}

func TestTLSDecryptHTTP2(t *testing.T) {
	cert := g.SelfSigned(t, "example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}}
	cli := &tls.Config{ServerName: "example.test", InsecureSkipVerify: true, NextProtos: []string{"h2"}}
	creq, cresp := g.HTTP2Bytes()
	writes, kl := g.TLSExchange(t, srv, cli, creq, cresp)
	useKeys(t, kl)
	f := g.DefaultFlow()
	f.B.Port = 443
	c := load(t, g.TLSCapture(f, writes, 1400))
	for filter, want := range map[string]int{
		`http2.headers.path == "/movie.mp4"`:         1,
		`http2.headers.content_type == "image/jpeg"`: 1,
		`media.type == "image/jpeg"`:                 1,
		`tls.handshake.extensions_alpn_str == "h2"`:  -1,
	} {
		got := matches(t, c, filter)
		if (want >= 0 && len(got) != want) || (want < 0 && len(got) == 0) {
			t.Errorf("%s: %v", filter, got)
		}
	}
}

// useKeys makes the key log known to the next capture that is opened.
func useKeys(t *testing.T, kl []byte) {
	path := filepath.Join(t.TempDir(), "keys.log")
	if err := os.WriteFile(path, kl, 0o600); err != nil {
		t.Fatal(err)
	}
	keylog.Default.SetFiles(path)
	t.Cleanup(func() { keylog.Default.SetFiles() })
}
