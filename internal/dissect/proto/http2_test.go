package proto_test

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/export"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func h2Capture(t *testing.T, port uint16) []g.Packet {
	cli, srv := g.HTTP2Bytes()
	f := g.DefaultFlow()
	f.B.Port = port
	c := g.NewTCPConv(f, 1e9)
	c.Send(0, cli)
	c.Send(1, srv)
	c.Close()
	return c.Pkts
}

func TestHTTP2(t *testing.T) {
	for _, port := range []uint16{8083, 80} {
		c := load(t, h2Capture(t, port))
		for filter, want := range map[string]int{
			"http2":                              -1,
			"http2.type == 1":                    2, // both requests share a segment, both responses another
			`http2.headers.path == "/movie.mp4"`: 1, // needs the dynamic table of the first request
			`http2.headers.content_type == "image/jpeg"`:               1,
			`http2.headers.status == "200"`:                            1,
			`http2.headers.authority == "media.example"`:               1,
			`http2.request.full_uri == "http://media.example/pic.jpg"`: 2,
			`http2.body.reassembled.length == 10`:                      1,
			`media.type == "image/jpeg"`:                               1,
			`data-text-lines contains "hello video"`:                   1,
			"http2.streamid == 3":                                      -1,
			"http2.type == 4":                                          -1,
		} {
			got := matches(t, c, filter)
			if (want >= 0 && len(got) != want) || (want < 0 && len(got) == 0) {
				t.Errorf("port %d: %s: %v", port, filter, got)
			}
		}
	}
	c := load(t, h2Capture(t, 8083))
	resp := matches(t, c, `http2.headers.content_type == "image/jpeg"`)
	w := c.Session().NewWorker(dissect.Options{Full: true, Columns: true})
	pi := w.Dissect(c.Input(resp[0]))
	var b bytes.Buffer
	export.WriteTree(&b, &pi.Tree.Root)
	if !strings.Contains(b.String(), "Request in frame") || pi.Protocol() != "HTTP2" || !strings.Contains(pi.Info(), "HEADERS[1]: 200 OK") {
		t.Errorf("%q %q\n%s", pi.Protocol(), pi.Info(), b.String())
	}
}

func TestGRPC(t *testing.T) {
	var cli, srv bytes.Buffer
	cli.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	cf := http2.NewFramer(&cli, nil)
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{{":method", "POST"}, {":scheme", "http"}, {":authority", "svc"}, {":path", "/helloworld.Greeter/SayHello"}, {"content-type", "application/grpc"}} {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	cf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndHeaders: true})
	// message { string name = 1; "world" }
	msg := append([]byte{0x0a, 5}, "world"...)
	cf.WriteData(1, true, append([]byte{0, 0, 0, 0, byte(len(msg))}, msg...))
	_ = srv
	f := g.DefaultFlow()
	f.B.Port = 50051
	c := g.NewTCPConv(f, 1e9)
	c.Send(0, cli.Bytes())
	cap := load(t, c.Pkts)
	if got := matches(t, cap, `grpc.message_length == 7`); len(got) != 1 {
		t.Errorf("grpc message: %v", got)
	}
	if got := matches(t, cap, `protobuf.field.value.string == "world"`); len(got) != 1 {
		t.Errorf("protobuf string: %v", got)
	}
}
