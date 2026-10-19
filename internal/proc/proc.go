// Package proc attributes packets to local processes on Linux by sampling
// the kernel socket tables during a live capture (macOS gets exact process
// information from PKTAP instead).
package proc

import (
	"bufio"
	"encoding/hex"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

// Info identifies a process.
type Info struct {
	PID  int32
	Name string
}

type flowKey struct {
	proto  uint8
	local  netip.AddrPort
	remote netip.AddrPort
}

type portKey struct {
	proto uint8
	port  uint16
}

// Table maps flows to processes. It keeps every mapping it has seen, so
// short-lived connections stay attributed after they close.
type Table struct {
	mu    sync.RWMutex
	flows map[flowKey]Info
	ports map[portKey]Info // listening/unconnected sockets
}

// NewTable creates an empty table.
func NewTable() *Table {
	return &Table{flows: map[flowKey]Info{}, ports: map[portKey]Info{}}
}

// Lookup finds the local process of a packet's flow in either direction.
func (t *Table) Lookup(proto uint8, src netip.AddrPort, dst netip.AddrPort) (Info, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if i, ok := t.flows[flowKey{proto, src, dst}]; ok {
		return i, true
	}
	if i, ok := t.flows[flowKey{proto, dst, src}]; ok {
		return i, true
	}
	if i, ok := t.ports[portKey{proto, src.Port()}]; ok {
		return i, true
	}
	if i, ok := t.ports[portKey{proto, dst.Port()}]; ok {
		return i, true
	}
	return Info{}, false
}

// Socket is a parsed /proc/net entry.
type Socket struct {
	Local, Remote netip.AddrPort
	Inode         uint64
}

// ParseNet parses /proc/net/{tcp,udp}[6].
func ParseNet(r io.Reader) []Socket {
	var out []Socket
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		l, ok1 := parseAddr(f[1])
		rm, ok2 := parseAddr(f[2])
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if !ok1 || !ok2 || err != nil || inode == 0 {
			continue
		}
		out = append(out, Socket{Local: l, Remote: rm, Inode: inode})
	}
	return out
}

// parseAddr decodes "0100007F:0CEA" (IPv4) or 32-hex-digit IPv6 forms; the
// kernel prints each 32-bit word in host (little-endian) order.
func parseAddr(s string) (netip.AddrPort, bool) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	b, err := hex.DecodeString(ipHex)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.AddrPort{}, false
	}
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	ip, _ := netip.AddrFromSlice(b)
	return netip.AddrPortFrom(ip.Unmap(), uint16(port)), true
}

func (t *Table) add(proto uint8, s Socket, info Info) {
	if !s.Remote.Addr().IsUnspecified() || s.Remote.Port() != 0 {
		t.flows[flowKey{proto, s.Local, s.Remote}] = info
		return
	}
	t.ports[portKey{proto, s.Local.Port()}] = info
}
