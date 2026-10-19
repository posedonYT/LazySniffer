package dfilter_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/poseydon/lazysniffer/internal/dfilter"
	_ "github.com/poseydon/lazysniffer/internal/dissect/proto"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/store"
)

func gopacketTestdata(t *testing.T, name string) string {
	t.Helper()
	gp := filepath.Join(os.Getenv("HOME"), "go/pkg/mod/github.com/gopacket/gopacket@v1.7.4/pcap", name)
	if _, err := os.Stat(gp); err != nil {
		t.Skip("sample capture not available")
	}
	return gp
}

func load(t *testing.T, path string) *store.Capture {
	t.Helper()
	c, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Load(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	return c
}

func count(t *testing.T, c *store.Capture, filter string) int {
	t.Helper()
	f, err := dfilter.Compile(filter)
	if err != nil {
		t.Fatalf("compile %q: %v", filter, err)
	}
	got, err := engine.Filter(context.Background(), c, f, 1, uint32(c.Count()), nil)
	if err != nil {
		t.Fatal(err)
	}
	return len(got)
}

func TestFiltersOnHTTPCapture(t *testing.T) {
	c := load(t, gopacketTestdata(t, "test_ethernet.pcap"))
	total := c.Count()
	cases := []struct {
		filter string
		want   int
	}{
		{"", total},
		{"tcp", total},
		{"udp", 0},
		{"!udp", total},
		{"tcp.flags.syn == 1", 2},
		{"tcp.flags.syn == 1 && tcp.flags.ack == 0", 1},
		{"tcp.flags.syn == True and not tcp.flags.ack", 0}, // bare fields test presence, like Wireshark
		{"tcp.flags & 0x02", 2},
		{"tcp.port == 80", total},
		{"tcp.port in {80 443}", total},
		{"tcp.port in {1..79}", 0},
		{"tcp.srcport == 80", 5},
		{"tcp.dstport != 80", 5},
		{"ip.src == 10.1.1.1", 5},
		{"ip.addr == 10.1.1.0/24", total},
		{"ip.addr == 10.1.2.0/24", 0},
		{"ip.src == ip.dst", 0},
		{"tcp.len > 0", 3},
		{"tcp.payload contains \"HTTP\"", 2},
		{"tcp.payload contains 48:54:54:50", 2},
		{"frame contains \"GET\"", 1},
		{"tcp.payload matches \"^get /\"", 1},
		{"tcp.payload ~ \"(?-i)^get\"", 0},
		{"len(tcp.payload) > 100", 1},
		{"frame.len >= 74 && frame.len <= 74", 2},
		{"eth.src[0:3] == 58:6d:8f", 5},
		{"eth.src[0] == 58", 5},
		{"frame[12:2] == 08:00", total},
		{"ip.ttl * 2 == 128", total},
		{"{ip.len + 14} == frame.len", total},
		{"count(tcp.port) == 2", total},
		{"tcp.options.mss_val == 1460", 2},
		{"ip.proto == TCP", total},
		{"tcp.stream == 0", total},
		{"frame.number <= 3", 3},
		{"frame.number in {1 3 5}", 3},
		{"frame.protocols contains \"tcp\"", total},
		{"frame.time_relative < 0.002", 4},
		{"upper(frame.protocols) contains \"ETH\"", total},
		{"ip.src#1 == 10.1.1.2", 5},
		{"ip.src#2 == 10.1.1.2", 0},
		{"tcp.flags.str contains \"F\"", 2},
		{"all tcp.port > 79", total},
		{"any tcp.port < 81", total},
		{"tcp.port === 80", 0},
		{"tcp.port !== 80", total},
	}
	for _, tc := range cases {
		if got := count(t, c, tc.filter); got != tc.want {
			t.Errorf("%q: got %d, want %d", tc.filter, got, tc.want)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	bad := []string{
		"tcp.port == ",
		"tcp.port = 80",
		"foo.bar",
		"tcp.port == abc",
		"ip.src == 300.1.1.1",
		"(tcp",
		"tcp.port in {}",
		"tcp.flags.syn > 0",
		"\"abc\" == \"abc\"",
		"tcp.port matches 80",
		"len()",
		"eth.src == zz:zz",
	}
	for _, s := range bad {
		if _, err := dfilter.Compile(s); err == nil {
			t.Errorf("%q: expected an error", s)
		}
	}
	_, err := dfilter.Compile("foo.bar == 1")
	if e, ok := err.(*dfilter.Error); !ok || e.Unknown != "foo.bar" || e.Pos != 0 || e.Len != 7 {
		t.Errorf("unknown field error: %#v", err)
	}
}

func FuzzCompile(f *testing.F) {
	for _, s := range []string{"tcp.port == 80", "ip.addr in {1.2.3.4 10.0.0.0/8}", "frame[1:2] == aa:bb", "len(ip.src) > ${frame.len} || !udp"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		dfilter.Compile(s)
	})
}
