package proc

import (
	"net/netip"
	"strings"
	"testing"
)

const tcp4 = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   118        0 24367 1 0000000000000000 100 0 0 10 0
   1: 3C01A8C0:C2C4 22D97A8E:01BB 01 00000000:00000000 02:00000A4C 00000000  1000        0 99881 2 0000000000000000 20 4 30 10 -1
`

const tcp6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11223 1 0000000000000000 100 0 0 10 0
`

func TestParseNet(t *testing.T) {
	s := ParseNet(strings.NewReader(tcp4))
	if len(s) != 2 {
		t.Fatalf("got %d sockets", len(s))
	}
	if s[0].Local.String() != "127.0.0.1:3306" || s[0].Inode != 24367 {
		t.Errorf("listen socket: %v", s[0])
	}
	if s[1].Local.String() != "192.168.1.60:49860" || s[1].Remote.String() != "142.122.217.34:443" {
		t.Errorf("connected socket: %v -> %v", s[1].Local, s[1].Remote)
	}
	s6 := ParseNet(strings.NewReader(tcp6))
	if len(s6) != 1 || s6[0].Local.String() != "[::1]:22" {
		t.Errorf("ipv6: %v", s6)
	}
	tb := NewTable()
	tb.add(6, s[1], Info{PID: 42, Name: "curl"})
	tb.add(6, s[0], Info{PID: 7, Name: "mysqld"})
	if i, ok := tb.Lookup(6, netip.MustParseAddrPort("142.122.217.34:443"), netip.MustParseAddrPort("192.168.1.60:49860")); !ok || i.Name != "curl" {
		t.Errorf("reverse lookup: %v %v", i, ok)
	}
	if i, ok := tb.Lookup(6, netip.MustParseAddrPort("10.0.0.9:55555"), netip.MustParseAddrPort("127.0.0.1:3306")); !ok || i.Name != "mysqld" {
		t.Errorf("port lookup: %v %v", i, ok)
	}
}
