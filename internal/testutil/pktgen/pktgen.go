// Package pktgen builds synthetic packets and capture files for tests.
package pktgen

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"

	"github.com/poseydon/lazysniffer/internal/pcapio"
)

// TCP flag bits.
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
)

// Endpoint is one side of a flow.
type Endpoint struct {
	MAC  [6]byte
	IP   netip.Addr
	Port uint16
}

// Flow is a pair of endpoints; Rev swaps them.
type Flow struct{ A, B Endpoint }

// Rev returns the flow in the other direction.
func (f Flow) Rev() Flow { return Flow{f.B, f.A} }

// DefaultFlow is 10.0.0.1:40000 → 10.0.0.2:80.
func DefaultFlow() Flow {
	return Flow{
		A: Endpoint{MAC: [6]byte{0x02, 0, 0, 0, 0, 1}, IP: netip.MustParseAddr("10.0.0.1"), Port: 40000},
		B: Endpoint{MAC: [6]byte{0x02, 0, 0, 0, 0, 2}, IP: netip.MustParseAddr("10.0.0.2"), Port: 80},
	}
}

func checksum(b []byte, sum uint32) uint16 {
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func pseudo(src, dst netip.Addr, proto byte, l int) uint32 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
	}
	add(src.AsSlice())
	add(dst.AsSlice())
	sum += uint32(proto) + uint32(l)
	return sum
}

// Ether wraps an IP packet in Ethernet II.
func Ether(src, dst [6]byte, etype uint16, payload []byte) []byte {
	b := make([]byte, 14, 14+len(payload))
	copy(b, dst[:])
	copy(b[6:], src[:])
	binary.BigEndian.PutUint16(b[12:], etype)
	return append(b, payload...)
}

// IPv4 builds an IPv4 header around payload.
func IPv4(src, dst netip.Addr, proto byte, id uint16, fragOff int, more bool, ttl byte, payload []byte) []byte {
	b := make([]byte, 20, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(b[4:], id)
	off := uint16(fragOff / 8)
	if more {
		off |= 0x2000
	}
	binary.BigEndian.PutUint16(b[6:], off)
	b[8], b[9] = ttl, proto
	copy(b[12:], src.AsSlice())
	copy(b[16:], dst.AsSlice())
	binary.BigEndian.PutUint16(b[10:], checksum(b, 0))
	return append(b, payload...)
}

// IPv6 builds an IPv6 header around payload.
func IPv6(src, dst netip.Addr, next byte, payload []byte) []byte {
	b := make([]byte, 40, 40+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(payload)))
	b[6], b[7] = next, 64
	copy(b[8:], src.AsSlice())
	copy(b[24:], dst.AsSlice())
	return append(b, payload...)
}

// TCPSeg builds a TCP segment (with checksum) for the flow direction.
func TCPSeg(f Flow, seq, ack uint32, flags byte, win uint16, opts, payload []byte) []byte {
	for len(opts)%4 != 0 {
		opts = append(opts, 1)
	}
	hl := 20 + len(opts)
	b := make([]byte, hl, hl+len(payload))
	binary.BigEndian.PutUint16(b[0:], f.A.Port)
	binary.BigEndian.PutUint16(b[2:], f.B.Port)
	binary.BigEndian.PutUint32(b[4:], seq)
	binary.BigEndian.PutUint32(b[8:], ack)
	b[12] = byte(hl/4) << 4
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:], win)
	copy(b[20:], opts)
	b = append(b, payload...)
	binary.BigEndian.PutUint16(b[16:], checksum(b, pseudo(f.A.IP, f.B.IP, 6, len(b))))
	return b
}

// TCP builds a full Ethernet/IP/TCP frame.
func TCP(f Flow, seq, ack uint32, flags byte, win uint16, opts, payload []byte) []byte {
	seg := TCPSeg(f, seq, ack, flags, win, opts, payload)
	if f.A.IP.Is6() {
		return Ether(f.A.MAC, f.B.MAC, 0x86dd, IPv6(f.A.IP, f.B.IP, 6, seg))
	}
	return Ether(f.A.MAC, f.B.MAC, 0x0800, IPv4(f.A.IP, f.B.IP, 6, 1, 0, false, 64, seg))
}

// UDP builds a full Ethernet/IP/UDP frame.
func UDP(f Flow, payload []byte) []byte {
	b := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(b[0:], f.A.Port)
	binary.BigEndian.PutUint16(b[2:], f.B.Port)
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(payload)))
	b = append(b, payload...)
	binary.BigEndian.PutUint16(b[6:], checksum(b, pseudo(f.A.IP, f.B.IP, 17, len(b))))
	if f.A.IP.Is6() {
		return Ether(f.A.MAC, f.B.MAC, 0x86dd, IPv6(f.A.IP, f.B.IP, 17, b))
	}
	return Ether(f.A.MAC, f.B.MAC, 0x0800, IPv4(f.A.IP, f.B.IP, 17, 7, 0, false, 64, b))
}

// UDPDatagram returns the raw UDP header+payload (for fragmenting).
func UDPDatagram(f Flow, payload []byte) []byte {
	b := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(b[0:], f.A.Port)
	binary.BigEndian.PutUint16(b[2:], f.B.Port)
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(payload)))
	b = append(b, payload...)
	binary.BigEndian.PutUint16(b[6:], checksum(b, pseudo(f.A.IP, f.B.IP, 17, len(b))))
	return b
}

// IPv4Fragments splits an IP payload into Ethernet frames of fragments.
func IPv4Fragments(f Flow, proto byte, id uint16, payload []byte, size int) [][]byte {
	size &^= 7
	var out [][]byte
	for off := 0; off < len(payload); off += size {
		end := min(off+size, len(payload))
		ip := IPv4(f.A.IP, f.B.IP, proto, id, off, end < len(payload), 64, payload[off:end])
		out = append(out, Ether(f.A.MAC, f.B.MAC, 0x0800, ip))
	}
	return out
}

// IPv6Fragments splits an upper-layer payload with Fragment headers.
func IPv6Fragments(f Flow, next byte, id uint32, payload []byte, size int) [][]byte {
	size &^= 7
	var out [][]byte
	for off := 0; off < len(payload); off += size {
		end := min(off+size, len(payload))
		fh := make([]byte, 8)
		fh[0] = next
		v := uint16(off/8) << 3
		if end < len(payload) {
			v |= 1
		}
		binary.BigEndian.PutUint16(fh[2:], v)
		binary.BigEndian.PutUint32(fh[4:], id)
		ip := IPv6(f.A.IP, f.B.IP, 44, append(fh, payload[off:end]...))
		out = append(out, Ether(f.A.MAC, f.B.MAC, 0x86dd, ip))
	}
	return out
}

// MSS and WS options for SYN segments.
func SynOpts(mss uint16, ws byte) []byte {
	return []byte{2, 4, byte(mss >> 8), byte(mss), 1, 3, 3, ws}
}

// Packet is a frame with its timestamp in nanoseconds.
type Packet struct {
	TS   int64
	Data []byte
}

// WritePcapng writes Ethernet packets to a temporary pcapng file.
func WritePcapng(t testing.TB, pkts []Packet) string {
	t.Helper()
	return WritePcapngLink(t, pcapio.LinkEthernet, pkts)
}

// WritePcapngLink writes packets with the given link type.
func WritePcapngLink(t testing.TB, link pcapio.LinkType, pkts []Packet) string {
	t.Helper()
	path := t.TempDir() + "/gen.pcapng"
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := pcapio.NewNgWriter(f, pcapio.SectionInfo{})
	w.AddInterface(pcapio.Interface{LinkType: link, SnapLen: 65535, Name: "gen0", FCSLen: -1})
	for _, p := range pkts {
		if err := w.WritePacket(pcapio.Record{TS: p.TS}, p.Data); err != nil {
			t.Fatal(err)
		}
	}
	w.Flush()
	f.Close()
	return path
}
