// Package resolve maps addresses and ports to names: MAC vendor prefixes
// (IEEE OUI), transport service names (IANA) and reverse DNS.
package resolve

//go:generate go run ./gen/main.go -out .

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	//go:embed oui.txt.gz
	ouiGz []byte
	//go:embed services.txt.gz
	servicesGz []byte

	ouiOnce sync.Once
	ouiMap  map[uint32]vendor
	svcOnce sync.Once
	svcMap  map[string]string
)

type vendor struct{ short, full string }

func loadGz(b []byte, fn func(line string)) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		fn(sc.Text())
	}
}

func loadOUI() {
	ouiMap = make(map[uint32]vendor, 41000)
	loadGz(ouiGz, func(line string) {
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			return
		}
		p, err := strconv.ParseUint(parts[0], 16, 32)
		if err != nil {
			return
		}
		ouiMap[uint32(p)] = vendor{parts[1], parts[2]}
	})
}

// Vendor returns the short and full manufacturer names of a MAC address.
func Vendor(mac []byte) (short, full string) {
	if len(mac) < 3 {
		return "", ""
	}
	ouiOnce.Do(loadOUI)
	v, ok := ouiMap[uint32(mac[0])<<16|uint32(mac[1])<<8|uint32(mac[2])]
	if !ok {
		return "", ""
	}
	return v.short, v.full
}

// EtherName renders a MAC address the way Wireshark does with MAC name
// resolution on: "Apple_1c:22:01". Well-known group addresses get names
// too; unknown vendors return "".
func EtherName(mac []byte) string {
	if len(mac) != 6 {
		return ""
	}
	if s := wellKnownMAC(mac); s != "" {
		return s
	}
	short, _ := Vendor(mac)
	if short == "" {
		return ""
	}
	return fmt.Sprintf("%s_%02x:%02x:%02x", short, mac[3], mac[4], mac[5])
}

func wellKnownMAC(m []byte) string {
	switch {
	case bytes.Equal(m, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}):
		return "Broadcast"
	case m[0] == 0x01 && m[1] == 0x00 && m[2] == 0x5e && m[3] < 0x80:
		return fmt.Sprintf("IPv4mcast_%02x:%02x:%02x", m[3], m[4], m[5])
	case m[0] == 0x33 && m[1] == 0x33:
		return fmt.Sprintf("IPv6mcast_%02x:%02x:%02x:%02x", m[2], m[3], m[4], m[5])
	case bytes.Equal(m, []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}):
		return "Spanning-tree-(for-bridges)_00"
	case bytes.Equal(m, []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}):
		return "LLDP_Multicast"
	case bytes.Equal(m, []byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}):
		return "CDP/VTP/DTP/PAgP/UDLD"
	}
	return ""
}

func loadServices() {
	svcMap = make(map[string]string, 12000)
	loadGz(servicesGz, func(line string) {
		if k, v, ok := strings.Cut(line, "\t"); ok {
			svcMap[k] = v
		}
	})
}

// Service returns the IANA service name of a port ("https"), or "".
func Service(port uint32, transport string) string {
	svcOnce.Do(loadServices)
	return svcMap[strconv.FormatUint(uint64(port), 10)+"/"+transport]
}

// DNS is an asynchronous reverse-DNS cache. Lookups never block the caller:
// Name returns "" until the answer arrives, then OnUpdate is called.
type DNS struct {
	mu       sync.Mutex
	cache    map[netip.Addr]string
	pending  map[netip.Addr]bool
	sem      chan struct{}
	version  atomic.Int64
	OnUpdate func()
	// Static names from the capture file (pcapng NRB) or a hosts file.
	static map[netip.Addr]string
}

// NewDNS creates a reverse DNS cache allowing a few concurrent lookups.
func NewDNS() *DNS {
	return &DNS{cache: map[netip.Addr]string{}, pending: map[netip.Addr]bool{}, sem: make(chan struct{}, 8), static: map[netip.Addr]string{}}
}

// Version increases whenever a new name was resolved.
func (d *DNS) Version() int64 { return d.version.Load() }

// AddStatic records a known name (from a name resolution block).
func (d *DNS) AddStatic(a netip.Addr, name string) {
	d.mu.Lock()
	d.static[a] = name
	d.mu.Unlock()
}

// Static returns a name from the capture file, if any.
func (d *DNS) Static(a netip.Addr) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.static[a]
}

// Name returns the cached host name of a, starting a lookup if needed.
func (d *DNS) Name(a netip.Addr) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s, ok := d.static[a]; ok {
		return s
	}
	if s, ok := d.cache[a]; ok {
		return s
	}
	if d.pending[a] || a.IsUnspecified() {
		return ""
	}
	d.pending[a] = true
	go d.lookup(a)
	return ""
}

func (d *DNS) lookup(a netip.Addr) {
	d.sem <- struct{}{}
	defer func() { <-d.sem }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, a.String())
	name := ""
	if err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}
	d.mu.Lock()
	d.cache[a] = name
	delete(d.pending, a)
	cb := d.OnUpdate
	d.mu.Unlock()
	if name != "" {
		d.version.Add(1)
	}
	if name != "" && cb != nil {
		cb()
	}
}
