package proto_test

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/poseydon/lazysniffer/internal/dissect"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestHTTP(t *testing.T) {
	f := g.DefaultFlow()
	c := g.NewTCPConv(f, 1e9)
	c.MSS = 64 // headers and bodies span many segments
	c.Send(0, []byte("GET /api/items?limit=10&sort=desc HTTP/1.1\r\nHost: shop.test\r\nAccept-Encoding: gzip\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"))
	body := gz(`{"items":[{"id":1,"name":"apple"},{"id":2,"name":"pear"}],"total":2}`)
	c.Send(1, append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(body))), body...))
	c.Send(0, []byte("POST /login HTTP/1.1\r\nHost: shop.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nuser=bob&password=s%3Dcret!"))
	c.Send(1, []byte("HTTP/1.1 302 Found\r\nLocation: /home\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n7\r\n, world\r\n0\r\n\r\n"))
	c.Send(0, []byte("HEAD /big HTTP/1.1\r\nHost: shop.test\r\n\r\n"))
	c.Send(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n"))
	c.Send(0, []byte("GET /ws HTTP/1.1\r\nHost: shop.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n\r\n"))
	c.Send(1, []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	key := []byte{1, 2, 3, 4}
	msg := []byte(`{"type":"hello"}`)
	masked := make([]byte, len(msg))
	for i := range msg {
		masked[i] = msg[i] ^ key[i%4]
	}
	c.Send(0, append(append([]byte{0x81, 0x80 | byte(len(msg))}, key...), masked...))
	c.Send(1, append([]byte{0x81, 5}, "world"...))
	c.Close()
	cap := load(t, c.Pkts)
	cases := []struct {
		filter string
		want   int
	}{
		{`http.request.method == "GET" && http.request.uri.path == "/api/items"`, 1},
		{`http.request.uri.query.parameter == "limit=10"`, 1},
		{`http.authbasic == "user:pass"`, 1},
		{`http.request && http.request.full_uri == "http://shop.test/api/items?limit=10&sort=desc"`, 1},
		{`http.response.code == 200 && http.content_encoding == "gzip"`, 1},
		{`json.value.string == "pear" && json.member_with_value == "total:2"`, 1},
		{`urlencoded-form.value == "s=cret!"`, 1},
		{`http.response.code == 302 && data-text-lines`, 0},
		{`http.chunk_size == 7`, 1},
		{`http.response_in`, 4},
		{`http.request_in && http.time`, 4},
		{`http.response.code == 200 && !http.file_data`, 1}, // HEAD response has no body
		{`websocket.opcode == 1 && websocket.payload.text == "{\"type\":\"hello\"}"`, 1},
		{`websocket.payload.text == "world"`, 1},
		{`json.value.string == "hello"`, 1},
	}
	for _, tc := range cases {
		if got := matches(t, cap, tc.filter); len(got) != tc.want {
			t.Errorf("%s: got %v (want %d frames)", tc.filter, got, tc.want)
		}
	}
	w := cap.Session().NewWorker(dissect.Options{Full: true, Columns: true})
	resp := matches(t, cap, "http.response.code == 302")
	if pi := w.Dissect(cap.Input(resp[0])); !strings.Contains(pi.Info(), "HTTP/1.1 302 Found") {
		t.Errorf("info %q", pi.Info())
	}
	req := matches(t, cap, `http.request.uri == "/login"`)
	if pi := w.Dissect(cap.Input(req[0])); pi.Info() != "POST /login HTTP/1.1  (application/x-www-form-urlencoded)" && !strings.HasPrefix(pi.Info(), "POST /login HTTP/1.1") {
		t.Errorf("info %q", pi.Info())
	}
}

func TestHTTPConnectTLS(t *testing.T) {
	f := g.DefaultFlow()
	f.B.Port = 3128
	cert := g.SelfSigned(t, "example.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	writes, _ := g.TLSExchange(t, &tls.Config{Certificates: []tls.Certificate{cert}}, &tls.Config{ServerName: "example.test", InsecureSkipVerify: true}, []byte("ping"), []byte("pong"))
	c := g.NewTCPConv(f, 1e9)
	c.Send(0, []byte("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n"))
	c.Send(1, []byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	for _, wr := range writes {
		dir := 0
		if wr.Server {
			dir = 1
		}
		c.Send(dir, wr.Data)
	}
	cap := load(t, c.Pkts)
	if got := matches(t, cap, `tls.handshake.extensions_server_name == "example.test"`); len(got) != 1 {
		t.Errorf("TLS inside CONNECT tunnel not dissected: %v", got)
	}
}
