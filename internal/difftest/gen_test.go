package difftest

import (
	"os"
	"testing"

	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func TestGenHTTPFile(t *testing.T) {
	out := os.Getenv("DIFFTEST_OUT")
	if out == "" {
		t.Skip()
	}
	f := g.DefaultFlow()
	c := g.NewTCPConv(f, 1e9)
	c.Send(0, []byte("GET /index.html?q=1 HTTP/1.1\r\nHost: example.org\r\nUser-Agent: curl/8\r\nAccept: */*\r\n\r\n"))
	c.Send(1, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 11\r\nServer: nginx\r\n\r\nhello world"))
	c.Close()
	b, _ := os.ReadFile(g.WritePcapng(t, c.Pkts))
	os.WriteFile(out, b, 0o644)
}
