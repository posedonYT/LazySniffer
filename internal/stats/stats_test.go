package stats

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	_ "github.com/poseydon/lazysniffer/internal/dissect/proto"
	"github.com/poseydon/lazysniffer/internal/pcapio"
	"github.com/poseydon/lazysniffer/internal/store"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func capture(t *testing.T) *store.Capture {
	f := g.DefaultFlow()
	c1 := g.NewTCPConv(f, 1e9)
	c1.Send(0, []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
	c1.Send(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
	c1.Close()
	f2 := g.DefaultFlow()
	f2.A.Port, f2.B.Port = 40001, 53
	pk := append([]g.Packet(nil), c1.Pkts...)
	pk = append(pk, g.Packet{TS: 5e9, Data: g.UDP(f2, []byte{1, 2, 3})}, g.Packet{TS: 6e9, Data: g.UDP(f2.Rev(), []byte{1, 2, 3, 4})})
	cp, err := store.Open(g.WritePcapng(t, pk))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cp.Close() })
	if err := cp.Load(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	return cp
}

func TestStats(t *testing.T) {
	c := capture(t)
	ctx := context.Background()
	tcp, err := Conversations(ctx, c, nil, TCP)
	if err != nil || len(tcp) != 1 {
		t.Fatalf("tcp convs %v %v", tcp, err)
	}
	cv := tcp[0]
	if cv.Packets() != uint64(len(c.File().Interfaces))*0+cv.PktsAB+cv.PktsBA || cv.PktsAB == 0 || cv.PktsBA == 0 || cv.PortA != 40000 || cv.PortB != 80 {
		t.Errorf("%+v", cv)
	}
	if cv.Filter() != "tcp.stream eq 0" {
		t.Error(cv.Filter())
	}
	udp, _ := Conversations(ctx, c, nil, UDP)
	if len(udp) != 1 || udp[0].PktsAB != 1 || udp[0].PktsBA != 1 {
		t.Errorf("%+v", udp)
	}
	ip, _ := Conversations(ctx, c, nil, IPv4)
	if len(ip) != 1 || ip[0].Packets() != uint64(c.Count()) {
		t.Errorf("ipv4 %+v (frames %d)", ip, c.Count())
	}
	eth, _ := Conversations(ctx, c, nil, Ethernet)
	if len(eth) != 1 {
		t.Errorf("eth %+v", eth)
	}
	eps, _ := Endpoints(ctx, c, nil, IPv4)
	if len(eps) != 2 || eps[0].Packets()+eps[1].Packets() != 2*uint64(c.Count()) {
		t.Errorf("endpoints %+v", eps)
	}
	phs, err := Hierarchy(ctx, c, nil)
	if err != nil || phs.Packets != uint64(c.Count()) {
		t.Fatalf("phs %+v %v", phs, err)
	}
	names := map[string]bool{}
	var walk func(n *PHS)
	walk = func(n *PHS) {
		names[n.Name] = true
		for _, ch := range n.Children {
			walk(ch)
		}
	}
	walk(phs)
	for _, want := range []string{"eth", "ip", "tcp", "udp", "http", "data"} {
		if !names[want] {
			t.Errorf("hierarchy lacks %s: %v", want, names)
		}
	}
	bins, _ := Lengths(ctx, c, nil)
	var total uint64
	for _, b := range bins {
		total += b.Count
	}
	if total != uint64(c.Count()) {
		t.Errorf("lengths %v", bins)
	}
}

func TestIO(t *testing.T) {
	c := capture(t)
	r, err := IO(context.Background(), c, []IOSeries{
		{Name: "all", Metric: Packets},
		{Name: "udp", Filter: "udp", Metric: Bytes},
		{Name: "win", Filter: "tcp", Metric: Max, Field: "tcp.window_size_value"},
	}, 1e9)
	if err != nil {
		t.Fatal(err)
	}
	if r.Bins != 5 {
		t.Errorf("bins %d", r.Bins)
	}
	var all, udp float64
	for _, v := range r.Series[0] {
		all += v
	}
	for _, v := range r.Series[1] {
		udp += v
	}
	if all != float64(c.Count()) || udp == 0 {
		t.Errorf("all %v udp %v", all, udp)
	}
	if r.Series[1][3] == 0 || r.Series[1][4] == 0 || r.Series[1][0] != 0 {
		t.Errorf("udp bins %v", r.Series[1])
	}
	if r.Series[2][0] == 0 {
		t.Errorf("window %v", r.Series[2])
	}
	if _, err := IO(context.Background(), c, []IOSeries{{Filter: "nonsense ==="}}, 1e9); err == nil {
		t.Error("bad filter accepted")
	}
}

func TestTCPGraphData(t *testing.T) {
	c := capture(t)
	d, err := TCPGraphData(context.Background(), c, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Dir[0]) == 0 || len(d.Dir[1]) == 0 || d.Client != "10.0.0.1:40000" || d.Server != "10.0.0.2:80" {
		t.Fatalf("%+v", d)
	}
	var maxNxt float64
	for _, p := range d.Dir[0] {
		maxNxt = max(maxNxt, p.NxtSeq)
	}
	if maxNxt < 20 {
		t.Errorf("client bytes sent %v", maxNxt)
	}
	if _, err := TCPGraphData(context.Background(), c, 9); err == nil {
		t.Error("missing stream accepted")
	}
}

func voipCapture(t *testing.T) *store.Capture {
	cp, err := store.Open(g.WritePcapng(t, g.SampleVoIP()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cp.Close() })
	if err := cp.Load(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	return cp
}

func TestVoIP(t *testing.T) {
	c := voipCapture(t)
	if out := os.Getenv("DUMP_VOIP"); out != "" {
		b, _ := os.ReadFile(c.Path)
		os.WriteFile(out, b, 0o644)
	}
	streams, err := RTPStreams(context.Background(), c)
	if err != nil || len(streams) != 1 {
		t.Fatalf("streams %v %v", streams, err)
	}
	s := streams[0]
	if s.Packets != 47 || s.Expected != 50 || s.Lost != 3 || s.SeqErrors != 1 || s.SSRC != 0x11223344 || s.PayloadType != 0 || s.SetupFrame != 1 {
		t.Errorf("%+v", s)
	}
	if s.MaxDelta < 79 || s.MaxDelta > 81 || s.MaxJitter < 0.93 || s.MaxJitter > 0.94 || s.MinDelta < 19.9 || s.MeanJitter < 0.23 || s.MeanJitter > 0.24 {
		t.Errorf("delta %v jitter %v", s.MaxDelta, s.MaxJitter)
	}
	calls, err := VoIPCalls(context.Background(), c)
	if err != nil || len(calls) != 1 {
		t.Fatalf("calls %v %v", calls, err)
	}
	cl := calls[0]
	if cl.State != "COMPLETED" || cl.CallID != "abc@10.0.0.1" || len(cl.Frames) != 6 || len(cl.Streams) != 1 || !strings.Contains(cl.From, "alice") {
		t.Errorf("%+v", cl)
	}
}

func TestG711AndAudio(t *testing.T) {
	for in, want := range map[byte]int16{0xff: 0, 0x7f: 0, 0x00: -32124, 0x80: 32124} {
		if got := ulaw(in); got != want {
			t.Errorf("ulaw(%#x) = %d, want %d", in, got, want)
		}
	}
	for in, want := range map[byte]int16{0xd5: 8, 0x55: -8, 0xaa: 32256, 0x2a: -32256} {
		if got := alaw(in); got != want {
			t.Errorf("alaw(%#x) = %d, want %d", in, got, want)
		}
	}
	c := voipCapture(t)
	streams, _ := RTPStreams(context.Background(), c)
	pcm, err := RTPAudio(context.Background(), c, streams[0])
	if err != nil {
		t.Fatal(err)
	}
	// 47 received + 3 lost packets of 160 samples, the first byte of silence is 0
	if len(pcm) != 50*160 {
		t.Errorf("%d samples, want %d", len(pcm), 50*160)
	}
	var buf bytes.Buffer
	if err := WriteWAV(&buf, pcm, 8000); err != nil || buf.Len() != 44+len(pcm)*2 || string(buf.Bytes()[:4]) != "RIFF" {
		t.Errorf("wav %d %v", buf.Len(), err)
	}
}

func TestWLANTraffic(t *testing.T) {
	cp, err := store.Open(g.WritePcapngLink(t, pcapio.LinkIEEE80211Radiotap, g.SampleWLAN()))
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	cp.Load(context.Background(), nil)
	nets, err := WLANTraffic(context.Background(), cp)
	if err != nil {
		t.Fatal(err)
	}
	var ap *WLANNet
	for _, n := range nets {
		if n.BSSID == "00:11:22:33:44:55" {
			ap = n
		}
	}
	if ap == nil || ap.SSID != "lazynet" || ap.Channel != 6 || ap.Beacons != 1 || ap.Data < 1 || ap.SigMax != -60 {
		t.Errorf("%+v", nets)
	}
}
