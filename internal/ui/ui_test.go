package ui

import (
	"fmt"
	"github.com/poseydon/lazysniffer/internal/deep"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/poseydon/lazysniffer/internal/capture"
	"github.com/poseydon/lazysniffer/internal/config"
	_ "github.com/poseydon/lazysniffer/internal/dissect/proto"
	"github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func sample(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(os.Getenv("HOME"), "go/pkg/mod/github.com/gopacket/gopacket@v1.7.4/pcap", name)
	if _, err := os.Stat(p); err != nil {
		t.Skip("sample capture not available")
	}
	return p
}

// harness drives the model synchronously, running commands until idle.
type harness struct {
	t *testing.T
	m *App
}

func newHarness(t *testing.T, w, h int, path string) *harness {
	deep.Disabled = !useDeep
	flashDuration = time.Millisecond
	ifaceTickEvery = 0
	liveTickEvery = 20 * time.Millisecond
	t.Setenv("LAZYSNIFFER_CONFIG_DIR", t.TempDir())
	cfg := config.Defaults()
	cfg.Theme = "dark"
	m := New(cfg, Options{Path: path})
	hs := &harness{t: t, m: m}
	hs.send(tea.WindowSizeMsg{Width: w, Height: h})
	hs.run(m.Init())
	return hs
}

func (h *harness) run(cmd tea.Cmd) {
	deadline := time.Now().Add(10 * time.Second)
	queue := []tea.Cmd{cmd}
	for len(queue) > 0 && time.Now().Before(deadline) {
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		msg := c()
		switch msg := msg.(type) {
		case nil:
		case tea.BatchMsg:
			queue = append(queue, msg...)
		default:
			// Skip timers so tests do not wait for flash expiry.
			if _, ok := msg.(flashMsg); ok {
				continue
			}
			if isInternal(msg) {
				continue
			}
			_, next := h.m.Update(msg)
			queue = append(queue, next)
		}
	}
}

func isInternal(msg tea.Msg) bool {
	// Messages produced by Bubble Tea's own commands (background color
	// queries, clipboard) are handled by the runtime, not the model.
	switch msg.(type) {
	case loadMsg, filterMsg, colorRulesEditedMsg:
		return false
	}
	t := fmt.Sprintf("%T", msg)
	return strings.HasPrefix(t, "tea.") || strings.HasPrefix(t, "*tea.") || strings.HasPrefix(t, "uv.")
}

func (h *harness) send(msg tea.Msg) {
	_, cmd := h.m.Update(msg)
	h.run(cmd)
}

func (h *harness) keys(keys ...string) {
	for _, k := range keys {
		h.send(keyMsg(k))
	}
}

func (h *harness) typeText(s string) {
	for _, r := range s {
		h.send(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
}

func keyMsg(k string) tea.KeyPressMsg {
	switch k {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case "right":
		return tea.KeyPressMsg{Code: tea.KeyRight}
	case "left":
		return tea.KeyPressMsg{Code: tea.KeyLeft}
	case "f10":
		return tea.KeyPressMsg{Code: tea.KeyF10}
	case "backspace":
		return tea.KeyPressMsg{Code: tea.KeyBackspace}
	}
	if strings.HasPrefix(k, "ctrl+") {
		return tea.KeyPressMsg{Code: rune(k[5]), Mod: tea.ModCtrl}
	}
	r := []rune(k)[0]
	return tea.KeyPressMsg{Code: r, Text: k}
}

func (h *harness) screen() string {
	v := h.m.View()
	return ansi.Strip(v.Content)
}

func (h *harness) snap(name string) string {
	s := h.screen()
	if dir := os.Getenv("LAZYSNIFFER_SNAPSHOTS"); dir != "" {
		os.WriteFile(filepath.Join(dir, name+".txt"), []byte(s), 0o644)
	}
	return s
}

func TestMainScreen(t *testing.T) {
	h := newHarness(t, 140, 40, sample(t, "test_ethernet.pcap"))
	s := h.snap("01-main")
	for _, want := range []string{"Packets", "Details", "Bytes", "44644 → 80 [SYN]", "Filter", "File  Edit  View"} {
		if !strings.Contains(s, want) {
			t.Errorf("main screen lacks %q:\n%s", want, s)
		}
	}
	if n := len(strings.Split(s, "\n")); n > 40 {
		t.Errorf("screen has %d lines, want at most 40", n)
	}
	for i, line := range strings.Split(s, "\n") {
		if w := ansi.StringWidth(line); w > 140 {
			t.Errorf("line %d is %d cells wide", i, w)
		}
	}

	// Move to the HTTP request and expand TCP in the details pane.
	h.keys("down", "down", "down", "enter")
	h.keys("down", "down", "down", "right")
	s = h.snap("02-details")
	if !strings.Contains(s, "▼ Transmission Control Protocol") {
		t.Errorf("TCP not expanded:\n%s", s)
	}

	// Apply a filter through the filter bar.
	h.keys("esc", "/")
	h.typeText("tcp.len > 0")
	h.keys("enter")
	s = h.snap("03-filtered")
	if h.m.filter == nil || len(h.m.displayed) != 3 {
		t.Fatalf("filter not applied: %d displayed\n%s", len(h.m.displayed), s)
	}
	if !strings.Contains(s, "Displayed: 3") {
		t.Errorf("status lacks Displayed count:\n%s", s)
	}

	// Invalid filter shows an error and is not applied.
	h.keys("/")
	h.typeText(" && foo.bar")
	s = h.snap("04-invalid")
	if !strings.Contains(s, "invalid") || !strings.Contains(s, "not a valid protocol or protocol field") {
		t.Errorf("invalid filter not reported:\n%s", s)
	}
	h.keys("esc")

	// Menu bar.
	h.keys("f10")
	s = h.snap("05-menu")
	if !strings.Contains(s, "Open…") {
		t.Errorf("File menu not open:\n%s", s)
	}
	h.keys("esc")

	// Command palette.
	h.send(tea.KeyPressMsg{Code: 'p', Mod: tea.ModCtrl})
	h.typeText("time disp")
	s = h.snap("06-palette")
	if !strings.Contains(s, "Time Display Format") {
		t.Errorf("palette did not find the command:\n%s", s)
	}
	h.keys("enter")
	s = h.snap("07-timefmt")
	if !strings.Contains(s, "Seconds Since Epoch") {
		t.Errorf("time format dialog missing:\n%s", s)
	}
	h.keys("esc")

	// Help.
	h.keys("?")
	s = h.snap("08-help")
	if !strings.Contains(s, "Keyboard") && !strings.Contains(s, "Panes") {
		t.Errorf("help missing:\n%s", s)
	}
}

func TestLayouts(t *testing.T) {
	for _, sz := range [][2]int{{200, 50}, {100, 30}, {80, 24}, {60, 18}} {
		h := newHarness(t, sz[0], sz[1], sample(t, "test_dns.pcap"))
		s := h.snap(fmt.Sprintf("layout-%dx%d", sz[0], sz[1]))
		lines := strings.Split(s, "\n")
		if len(lines) > sz[1] {
			t.Errorf("%v: %d lines", sz, len(lines))
		}
		for i, l := range lines {
			if ansi.StringWidth(l) > sz[0] {
				t.Errorf("%v: line %d too wide (%d)", sz, i, ansi.StringWidth(l))
			}
		}
		if !strings.Contains(s, "109.194.160.4") {
			t.Errorf("%v: packet list missing:\n%s", sz, s)
		}
	}
}

func TestStartScreen(t *testing.T) {
	h := newHarness(t, 120, 35, "")
	s := h.snap("00-start")
	if !strings.Contains(s, "Open a capture file") {
		t.Errorf("start screen:\n%s", s)
	}
}

func TestLiveReplay(t *testing.T) {
	path := sample(t, "test_ethernet.pcap")
	// The helper is this test binary's parent command; build it once.
	bin := filepath.Join(t.TempDir(), "lazysniffer")
	out, err := exec.Command("go", "build", "-o", bin, "github.com/poseydon/lazysniffer/cmd/lazysniffer").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	helper := filepath.Join(filepath.Dir(bin), "lazysniffer-dumpcap")
	if err := os.Symlink(bin, helper); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, 140, 40, "")
	t.Setenv("TMPDIR", t.TempDir())
	h.run(h.m.startCapture(capture.Options{Replay: path, ReplaySpeed: 0}))
	s := h.snap("10-live")
	if h.m.cap == nil || h.m.cap.Count() != 10 {
		t.Fatalf("live capture did not load 10 packets:\n%s", s)
	}
	if !h.m.capt.unsaved || h.m.capt.tempFile == "" {
		t.Fatalf("live capture should be marked unsaved")
	}
	// Quitting asks to save.
	h.keys("q")
	s = h.snap("11-ask-save")
	if !strings.Contains(s, "Unsaved packets") {
		t.Fatalf("no save prompt:\n%s", s)
	}
	h.keys("esc")
	h.m.discardTemp()
}

func TestFollowAndExpert(t *testing.T) {
	f := pktgen.DefaultFlow()
	r := f.Rev()
	var pkts []pktgen.Packet
	ts := int64(1e9)
	add := func(b []byte) { ts += 50e6; pkts = append(pkts, pktgen.Packet{TS: ts, Data: b}) }
	add(pktgen.TCP(f, 100, 0, pktgen.SYN, 65535, nil, nil))
	add(pktgen.TCP(r, 900, 101, pktgen.SYN|pktgen.ACK, 65535, nil, nil))
	add(pktgen.TCP(f, 101, 901, pktgen.ACK, 65535, nil, nil))
	add(pktgen.TCP(f, 101, 901, pktgen.ACK|pktgen.PSH, 65535, nil, []byte("GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n")))
	add(pktgen.TCP(f, 101, 901, pktgen.ACK|pktgen.PSH, 65535, nil, []byte("GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n")))
	add(pktgen.TCP(r, 901, 144, pktgen.ACK|pktgen.PSH, 65535, nil, []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")))
	add(pktgen.TCP(f, 144, 950, pktgen.RST|pktgen.ACK, 0, nil, nil))
	path := pktgen.WritePcapng(t, pkts)
	h := newHarness(t, 140, 40, path)
	h.keys("down", "down", "down", "f")
	s := h.snap("20-follow")
	for _, want := range []string{"Follow TCP Stream (tcp.stream eq 0)", "GET /index.html HTTP/1.1", "HTTP/1.1 200 OK", "client 10.0.0.1:40000", "2 Follow TCP 0"} {
		if !strings.Contains(s, want) {
			t.Errorf("follow view lacks %q:\n%s", want, s)
		}
	}
	if strings.Count(s, "GET /index.html") != 1 {
		t.Errorf("retransmitted request shown twice:\n%s", s)
	}
	if h.m.filter == nil || h.m.filter.Text != "tcp.stream eq 0" {
		t.Errorf("follow should filter the packet list")
	}
	h.keys("m")
	s = h.snap("21-follow-hex")
	if !strings.Contains(s, "00000000  47 45 54 20") {
		t.Errorf("hex mode:\n%s", s)
	}
	h.keys("esc")
	if len(h.m.tabs) != 0 || (h.m.filter != nil && !h.m.filter.Empty()) {
		t.Errorf("closing follow should restore the filter, got tabs=%d filter=%v", len(h.m.tabs), h.m.filter)
	}
	h.keys("!")
	s = h.snap("22-expert")
	for _, want := range []string{"Expert Information", "Connection reset (RST)", "retransmission", "Warning"} {
		if !strings.Contains(s, want) {
			t.Errorf("expert view lacks %q:\n%s", want, s)
		}
	}
	// Expand the first group and jump to its packet.
	h.keys("enter", "down", "enter")
	if h.m.tab != -1 || h.m.selected == 0 {
		t.Errorf("enter on an expert item should go to the packet")
	}
}

func TestStatisticsTabs(t *testing.T) {
	h := newHarness(t, 160, 40, sample(t, "test_dns.pcap"))
	h.keys("ctrl+t")
	s := h.snap("30-conversations")
	for _, want := range []string{"Conversations", "UDP", "Address A", "109.194.160.4:57766"} {
		if !strings.Contains(s, want) {
			t.Errorf("conversations lacks %q:\n%s", want, s)
		}
	}
	h.keys("s")
	h.keys("esc")
	h.keys("ctrl+p")
	h.typeText("protocol hier")
	h.keys("enter")
	s = h.snap("31-hierarchy")
	for _, want := range []string{"Protocol Hierarchy", "Domain Name System (dns)", "100.0"} {
		if !strings.Contains(s, want) && !strings.Contains(s, strings.ToLower(want)) {
			t.Errorf("hierarchy lacks %q:\n%s", want, s)
		}
	}
}

func TestExportObjectsTab(t *testing.T) {
	f := pktgen.DefaultFlow()
	c := pktgen.NewTCPConv(f, 1e9)
	c.Send(0, []byte("GET /logo.png HTTP/1.1\r\nHost: img.example\r\n\r\n"))
	c.Send(1, []byte("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 4\r\n\r\nPNG!"))
	c.Close()
	h := newHarness(t, 160, 40, pktgen.WritePcapng(t, c.Pkts))
	h.keys("ctrl+e")
	s := h.snap("32-objects")
	for _, want := range []string{"Export Objects", "img.example", "image/png", "logo.png"} {
		if !strings.Contains(s, want) {
			t.Errorf("objects lacks %q:\n%s", want, s)
		}
	}
}

func TestIOGraphTab(t *testing.T) {
	h := newHarness(t, 160, 40, sample(t, "test_dns.pcap"))
	h.keys("ctrl+p")
	h.typeText("i/o graph")
	h.keys("enter")
	s := h.snap("33-iograph")
	for _, want := range []string{"I/O Graph", "All packets", "interval", "⣀"} {
		if !strings.Contains(s, want) && want != "⣀" {
			t.Errorf("io graph lacks %q:\n%s", want, s)
		}
	}
	if !strings.ContainsAny(s, "⠁⠂⠄⡀⠈⠐⠠⢀⣀⣤⣶⣿⠉⠒⠤⣉⠑⠊⠢⠔⡠⢄⠱⡰⢎⠎⠜⢆") {
		t.Errorf("no braille plot:\n%s", s)
	}
	h.keys("right", "i", "n")
	h.typeText("udp")
	h.keys("enter")
	h.keys("enter") // Packets
	s = h.snap("34-iograph-series")
	if !strings.Contains(s, "udp") {
		t.Errorf("new series missing:\n%s", s)
	}
}

func TestTCPGraphTab(t *testing.T) {
	f := pktgen.DefaultFlow()
	c := pktgen.NewTCPConv(f, 1e9)
	c.Step = 50e6
	for i := 0; i < 20; i++ {
		c.Send(0, make([]byte, 1000))
	}
	c.Close()
	h := newHarness(t, 150, 40, pktgen.WritePcapng(t, c.Pkts))
	h.keys("down", "down", "down", "down")
	h.keys("ctrl+p")
	h.typeText("tcp stream graph")
	h.keys("enter")
	s := h.snap("35-tcpgraph")
	for _, want := range []string{"TCP Stream Graph", "Time-Sequence", "10.0.0.1:40000 → 10.0.0.2:80"} {
		if !strings.Contains(s, want) {
			t.Errorf("tcp graph lacks %q:\n%s", want, s)
		}
	}
	h.keys("g", "g", "g")
	s = h.snap("36-tcpgraph-window")
	if !strings.Contains(s, "window size") {
		t.Errorf("window graph missing:\n%s", s)
	}
}

func TestFlowGraphTab(t *testing.T) {
	f := pktgen.DefaultFlow()
	c := pktgen.NewTCPConv(f, 1e9)
	c.Send(0, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	c.Send(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	c.Close()
	h := newHarness(t, 150, 30, pktgen.WritePcapng(t, c.Pkts))
	h.keys("ctrl+p")
	h.typeText("flow graph")
	h.keys("enter")
	s := h.snap("37-flow")
	for _, want := range []string{"Flow Graph", "10.0.0.1", "10.0.0.2", "[SYN]", "▶", "◀", "GET / HTTP/1.1"} {
		if !strings.Contains(s, want) {
			t.Errorf("flow lacks %q:\n%s", want, s)
		}
	}
}

var useDeep bool

func TestDeepEngine(t *testing.T) {
	useDeep = true
	defer func() { useDeep = false; deep.Disabled = true }()
	if !deep.Available() {
		t.Skip("Wireshark's sharkd is not installed")
	}
	f := pktgen.DefaultFlow()
	c := pktgen.NewTCPConv(f, 1e9)
	c.Send(0, []byte("GET /deep HTTP/1.1\r\nHost: x\r\n\r\n"))
	c.Close()
	h := newHarness(t, 150, 40, pktgen.WritePcapng(t, c.Pkts))
	defer h.m.closeDeep()
	h.keys("/")
	h.typeText("frame.section_number == 1")
	h.keys("enter")
	deadline := time.Now().Add(10 * time.Second)
	var s string
	for time.Now().Before(deadline) {
		s = h.snap("40-deep-filter")
		if strings.Contains(s, "deep filter") {
			break
		}
		time.Sleep(50 * time.Millisecond)
		h.run(h.m.onIfaceTick())
	}
	if !strings.Contains(s, "deep filter") {
		t.Errorf("deep filter did not run:\n%s", s)
	}
	h.keys("down", "down", "down", "D")
	s = h.snap("41-deep-frame")
	for _, want := range []string{"Deep dissection (Wireshark)", "Hypertext Transfer Protocol", "Frame 4"} {
		if !strings.Contains(s, want) {
			t.Errorf("deep tab lacks %q:\n%s", want, s)
		}
	}
}

func TestTelephonyTabs(t *testing.T) {
	h := newHarness(t, 170, 40, pktgen.WritePcapng(t, pktgen.SampleVoIP()))
	h.keys("ctrl+p")
	h.typeText("voip calls")
	h.keys("enter")
	s := h.snap("42-voip")
	for _, want := range []string{"VoIP Calls", "COMPLETED", "alice", "SIP"} {
		if !strings.Contains(s, want) {
			t.Errorf("voip lacks %q:\n%s", want, s)
		}
	}
	h.keys("esc")
	h.keys("ctrl+p")
	h.typeText("rtp streams")
	h.keys("enter")
	s = h.snap("43-rtp")
	for _, want := range []string{"RTP Streams", "0x11223344", "g711U", "3 (6.0%)", "X"} {
		if !strings.Contains(s, want) {
			t.Errorf("rtp lacks %q:\n%s", want, s)
		}
	}
}

func TestExtcapLive(t *testing.T) {
	var ifc *capture.ExtcapIface
	for _, i := range capture.ExtcapInterfaces() {
		if i.Name == "randpkt" {
			i := i
			ifc = &i
		}
	}
	if ifc == nil {
		t.Skip("randpktdump (Wireshark extcap) is not installed")
	}
	h := newHarness(t, 150, 40, "")
	h.keys("X")
	if s := h.snap("44-extcap-list"); !strings.Contains(s, "Capture via extcap") {
		t.Fatalf("extcap list missing:\n%s", s)
	}
	h.keys("esc")
	args, err := capture.ExtcapArgs(*ifc)
	if err != nil {
		t.Fatal(err)
	}
	vals := map[string]string{}
	for _, a := range args {
		vals[a.Call] = a.Default
	}
	vals["--count"] = "50"
	h.run(h.m.extcapForm(*ifc, args, vals))
	s := h.snap("45-extcap-form")
	if !strings.Contains(s, "Start capture") || !strings.Contains(s, "--maxbytes") {
		t.Fatalf("extcap form missing:\n%s", s)
	}
	h.keys("enter") // Start capture
	deadline := time.Now().Add(15 * time.Second)
	for h.m.capt.live != nil && time.Now().Before(deadline) {
		h.run(h.m.listenLive(h.m.capt.live)) // pump the next capture event
	}
	s = h.snap("46-extcap-live")
	if h.m.cap == nil || h.m.cap.Count() != 50 {
		n := 0
		if h.m.cap != nil {
			n = h.m.cap.Count()
		}
		t.Fatalf("captured %d packets through extcap, want 50:\n%s", n, s)
	}
	if h.m.capt.live != nil {
		h.m.capt.live.Stop()
	}
	h.m.discardTemp()
}

func TestDecodeAsAndEnabledProtocols(t *testing.T) {
	f := pktgen.DefaultFlow()
	f.A.Port, f.B.Port = 40000, 5555
	dnsq := []byte("\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01")
	path := pktgen.WritePcapng(t, []pktgen.Packet{{TS: 1e9, Data: pktgen.UDP(f, dnsq)}})
	defer applyProtocolPrefs(config.Defaults())
	count := func(cfg *config.Config, filter string) int {
		h := newHarness(t, 140, 30, path)
		applyProtocolPrefs(cfg)
		h.run(h.m.reload())
		h.keys("/")
		h.typeText(filter)
		h.keys("enter")
		return len(h.m.displayed)
	}
	if n := count(config.Defaults(), "dns"); n != 0 {
		t.Fatalf("port 5555 should not be DNS yet (%d)", n)
	}
	cfg := config.Defaults()
	cfg.DecodeAs = []config.DecodeAsEntry{{Table: "udp.port", Value: 5555, Handle: "dns"}}
	if n := count(cfg, "dns"); n != 1 {
		t.Fatalf("Decode As did not take effect (%d)", n)
	}
	cfg.DisabledProtocols = []string{"dns"}
	if n := count(cfg, "dns"); n != 0 {
		t.Fatalf("a disabled protocol was still dissected (%d)", n)
	}
}

func TestPowerUserDialogs(t *testing.T) {
	h := newHarness(t, 150, 40, sample(t, "test_ethernet.pcap"))
	h.keys("down", "down", "down")
	h.keys("ctrl+p")
	h.typeText("firewall")
	h.keys("enter")
	h.keys("enter") // iptables
	s := h.snap("50-firewall")
	for _, want := range []string{"iptables -A INPUT", "-j DROP", "10.1.1.2"} {
		if !strings.Contains(s, want) {
			t.Errorf("firewall lacks %q:\n%s", want, s)
		}
	}
	h.keys("esc", "esc", "esc")
	// time shift moves the displayed time
	before := h.m.selPI.TS
	h.m.cap.SetTimeShift(3600e9)
	h.m.dissectSelected()
	if h.m.selPI.TS != before+3600e9 {
		t.Errorf("time shift not applied: %d vs %d", h.m.selPI.TS, before)
	}
	// expression builder fills the filter bar
	h.m.cap.SetTimeShift(0)
	h.run(h.m.expressionInsert("tcp.port == 80"))
	if !strings.Contains(h.m.fbar.text(), "tcp.port == 80") {
		t.Errorf("expression not inserted: %q", h.m.fbar.text())
	}
}
