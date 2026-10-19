package deep

import (
	"os"
	"strings"
	"testing"

	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func TestSharkd(t *testing.T) {
	if !Available() {
		t.Skip("sharkd is not installed")
	}
	f := g.DefaultFlow()
	c := g.NewTCPConv(f, 1e9)
	c.Send(0, []byte("GET /deep HTTP/1.1\r\nHost: example.org\r\n\r\n"))
	c.Send(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	path := g.WritePcapng(t, c.Pkts)
	cl, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if err := cl.Load(path); err != nil {
		t.Fatal(err)
	}
	if err := cl.Check(`http.request.method == "GET"`); err != nil {
		t.Errorf("check: %v", err)
	}
	if err := cl.Check("nosuchfield == 1"); err == nil || !(strings.Contains(err.Error(), "not a valid") || strings.Contains(err.Error(), "invalid")) {
		t.Errorf("bad filter accepted: %v", err)
	}
	frames, err := cl.Frames("http")
	if err != nil || len(frames) != 2 {
		t.Fatalf("frames %v %v", frames, err)
	}
	fr, err := cl.Frame(frames[0])
	if err != nil || len(fr.Tree) == 0 || len(fr.Bytes) == 0 {
		t.Fatalf("frame %v %v", fr, err)
	}
	found := false
	Walk(fr.Tree, func(n *Node, _ int) bool {
		if n.Field == "http.request.uri" {
			found = true
		}
		return true
	})
	if !found {
		t.Error("http.request.uri not in the deep tree")
	}
	fs, err := cl.Fields("http.request.m")
	if err != nil || len(fs) == 0 {
		t.Errorf("fields %v %v", fs, err)
	}
	if raw, err := cl.Tap("conv:TCP", ""); err != nil || !strings.Contains(string(raw), "conv") {
		t.Errorf("tap %s %v", raw, err)
	}
	_ = os.Remove(path)
}
