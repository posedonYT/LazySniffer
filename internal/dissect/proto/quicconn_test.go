package proto_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/poseydon/lazysniffer/internal/keylog"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func TestQUICDecrypt1RTT(t *testing.T) {
	f := g.DefaultFlow()
	f.B.Port = 443
	q := g.NewQUICConn(t, f, "quic.example.test", "h3")
	q.SendStream(true, 0, []byte("hello quic stream"), true)
	q.SendStream(false, 0, []byte("response bytes"), true)
	kf := filepath.Join(t.TempDir(), "keys.log")
	os.WriteFile(kf, q.Keylog.Bytes(), 0o600)
	t.Run("without keys", func(t *testing.T) {
		c := load(t, q.Packets)
		if got := matches(t, c, `tls.handshake.extensions_server_name == "quic.example.test"`); len(got) != 1 {
			t.Errorf("SNI: %v", got)
		}
		if got := matches(t, c, "quic.frame_type == 8"); len(got) != 0 {
			t.Errorf("1-RTT frames visible without keys: %v", got)
		}
		if got := matches(t, c, "tls.handshake.type == 2"); len(got) != 1 {
			t.Errorf("Initial ServerHello should decrypt without keys: %v", got)
		}
		if got := matches(t, c, "tls.handshake.type == 11"); len(got) != 0 {
			t.Errorf("Handshake packets decrypted without keys: %v", got)
		}
	})
	t.Run("with keys", func(t *testing.T) {
		keylog.Default.SetFiles(kf)
		defer keylog.Default.SetFiles()
		c := load(t, q.Packets)
		for filter, want := range map[string]int{
			"tls.handshake.type == 11":                  1, // Certificate, Handshake space
			"tls.handshake.type == 20":                  2, // both Finished messages
			"quic.stream.stream_id == 0":                2,
			"quic.stream_data contains \"hello quic\"":  1,
			"quic.stream_data contains \"response by\"": 1,
		} {
			if got := matches(t, c, filter); len(got) != want {
				t.Errorf("%s: %v (want %d)", filter, got, want)
			}
		}
	})
}

func TestHTTP3(t *testing.T) {
	f := g.DefaultFlow()
	f.B.Port = 443
	q := g.NewQUICConn(t, f, "h3.example", "h3")
	img := bytes.Repeat([]byte{0xff, 0xd8, 0xff, 0xe0}, 300)
	q.HTTP3Exchange("/pic.jpg", "image/jpeg", img)
	kf := filepath.Join(t.TempDir(), "keys.log")
	os.WriteFile(kf, q.Keylog.Bytes(), 0o600)
	keylog.Default.SetFiles(kf)
	defer keylog.Default.SetFiles()
	c := load(t, q.Packets)
	for filter, want := range map[string]int{
		`http3.frame_type == 4`:                                  2, // both SETTINGS
		`http3.headers.method == "GET"`:                          1,
		`http3.headers.path == "/pic.jpg"`:                       1,
		`http3.headers.authority == "h3.example"`:                1,
		`http3.header.header.name == "x-custom"`:                 1, // from the dynamic table
		`http3.headers.header.value == "hello"`:                  1,
		`http3.headers.status == 200`:                            1,
		`http3.headers.content_type == "image/jpeg"`:             1,
		`http3.request.full_uri == "https://h3.example/pic.jpg"`: 1,
		`http3.frame_type == 0`:                                  2,
	} {
		if got := matches(t, c, filter); len(got) != want {
			t.Errorf("%s: %v (want %d)", filter, got, want)
		}
	}
}
