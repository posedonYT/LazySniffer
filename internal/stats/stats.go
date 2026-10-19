// Package stats computes the statistics windows of Wireshark's Statistics
// menu from a capture: conversations, endpoints, protocol hierarchy and
// packet length distribution.
package stats

import (
	"context"
	"fmt"
	"sort"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/store"
)

// Kind selects the protocol layer of conversations and endpoints.
type Kind int

const (
	Ethernet Kind = iota
	IPv4
	IPv6
	TCP
	UDP
)

var Kinds = []Kind{Ethernet, IPv4, IPv6, TCP, UDP}

func (k Kind) String() string {
	return [...]string{"Ethernet", "IPv4", "IPv6", "TCP", "UDP"}[k]
}

// Conv is one bidirectional conversation.
type Conv struct {
	A, B         dissect.Address
	PortA, PortB uint32
	PktsAB       uint64
	PktsBA       uint64
	BytesAB      uint64
	BytesBA      uint64
	FirstTS      int64 // relative to the capture start, ns
	LastTS       int64
	FirstFrame   uint32
	Stream       int // TCP/UDP stream index, -1 otherwise
	Kind         Kind
}

func (c *Conv) Packets() uint64 { return c.PktsAB + c.PktsBA }
func (c *Conv) Bytes() uint64   { return c.BytesAB + c.BytesBA }

// Duration in seconds.
func (c *Conv) Duration() float64 { return float64(c.LastTS-c.FirstTS) / 1e9 }

// Filter returns the display filter that selects the conversation.
func (c *Conv) Filter() string {
	switch c.Kind {
	case Ethernet:
		return fmt.Sprintf("eth.addr == %s && eth.addr == %s", c.A, c.B)
	case IPv4:
		return fmt.Sprintf("ip.addr == %s && ip.addr == %s", c.A, c.B)
	case IPv6:
		return fmt.Sprintf("ipv6.addr == %s && ipv6.addr == %s", c.A, c.B)
	case TCP:
		if c.Stream >= 0 {
			return fmt.Sprintf("tcp.stream eq %d", c.Stream)
		}
	case UDP:
		if c.Stream >= 0 {
			return fmt.Sprintf("udp.stream eq %d", c.Stream)
		}
	}
	return ""
}

type convKey struct {
	a, b   dissect.Address
	pa, pb uint32
	stream int
}

// addrs extracts the endpoints of a frame for a kind.
func addrs(k Kind, pi *dissect.PacketInfo) (src, dst dissect.Address, sp, dp uint32, ok bool) {
	switch k {
	case Ethernet:
		if pi.DLSrc.IsZero() || pi.DLDst.IsZero() {
			return
		}
		return pi.DLSrc, pi.DLDst, 0, 0, true
	case IPv4:
		if pi.NetSrc.Type != dissect.AddrIPv4 {
			return
		}
		return pi.NetSrc, pi.NetDst, 0, 0, true
	case IPv6:
		if pi.NetSrc.Type != dissect.AddrIPv6 {
			return
		}
		return pi.NetSrc, pi.NetDst, 0, 0, true
	case TCP:
		if pi.PortType != dissect.PortTCP || pi.Conv == nil {
			return
		}
		return pi.Src, pi.Dst, pi.SrcPort, pi.DstPort, true
	case UDP:
		if pi.PortType != dissect.PortUDP || pi.Conv == nil {
			return
		}
		return pi.Src, pi.Dst, pi.SrcPort, pi.DstPort, true
	}
	return
}

func order(a, b dissect.Address, pa, pb uint32) bool {
	if c := a.Compare(b); c != 0 {
		return c < 0
	}
	return pa <= pb
}

// Conversations aggregates the frames (all when nil) by conversation.
func Conversations(ctx context.Context, c *store.Capture, frames []uint32, k Kind) ([]*Conv, error) {
	if frames == nil {
		frames = engine.AllFrames(c)
	}
	parts := make([]map[convKey]*Conv, engine.Workers())
	for i := range parts {
		parts[i] = map[convKey]*Conv{}
	}
	err := engine.Each(ctx, c, dissect.Options{Want: make([]bool, dissect.NumFields())}, frames,
		func(w int, num uint32, pi *dissect.PacketInfo) {
			src, dst, sp, dp, ok := addrs(k, pi)
			if !ok {
				return
			}
			stream := -1
			if (k == TCP || k == UDP) && pi.Conv != nil {
				stream = int(pi.Conv.Index)
			}
			key := convKey{stream: stream}
			fwd := order(src, dst, sp, dp)
			if fwd {
				key.a, key.b, key.pa, key.pb = src, dst, sp, dp
			} else {
				key.a, key.b, key.pa, key.pb = dst, src, dp, sp
			}
			if stream >= 0 {
				key = convKey{stream: stream}
			}
			cv := parts[w][key]
			if cv == nil {
				cv = &Conv{A: src, B: dst, PortA: sp, PortB: dp, FirstTS: pi.RelTS, FirstFrame: num, Stream: stream, Kind: k}
				if stream < 0 {
					cv.A, cv.B, cv.PortA, cv.PortB = key.a, key.b, key.pa, key.pb
				}
				parts[w][key] = cv
			}
			// Direction: A→B when the sender is endpoint A.
			fromA := src == cv.A && sp == cv.PortA
			if stream < 0 {
				fromA = src == cv.A
			}
			if fromA {
				cv.PktsAB++
				cv.BytesAB += uint64(pi.Len)
			} else {
				cv.PktsBA++
				cv.BytesBA += uint64(pi.Len)
			}
			if pi.RelTS < cv.FirstTS || cv.FirstFrame > num {
				cv.FirstTS, cv.FirstFrame = pi.RelTS, num
			}
			if pi.RelTS > cv.LastTS {
				cv.LastTS = pi.RelTS
			}
		})
	if err != nil {
		return nil, err
	}
	merged := map[convKey]*Conv{}
	for _, p := range parts {
		for key, cv := range p {
			m := merged[key]
			if m == nil {
				merged[key] = cv
				continue
			}
			// Workers may have seen the conversation from different sides.
			if cv.A == m.A && cv.PortA == m.PortA {
				m.PktsAB, m.PktsBA, m.BytesAB, m.BytesBA = m.PktsAB+cv.PktsAB, m.PktsBA+cv.PktsBA, m.BytesAB+cv.BytesAB, m.BytesBA+cv.BytesBA
			} else {
				m.PktsAB, m.PktsBA, m.BytesAB, m.BytesBA = m.PktsAB+cv.PktsBA, m.PktsBA+cv.PktsAB, m.BytesAB+cv.BytesBA, m.BytesBA+cv.BytesAB
			}
			if cv.FirstFrame < m.FirstFrame {
				m.FirstFrame, m.FirstTS = cv.FirstFrame, cv.FirstTS
				if !(cv.A == m.A && cv.PortA == m.PortA) {
					// The earlier sender becomes A.
					m.A, m.B, m.PortA, m.PortB = cv.A, cv.B, cv.PortA, cv.PortB
					m.PktsAB, m.PktsBA, m.BytesAB, m.BytesBA = m.PktsBA, m.PktsAB, m.BytesBA, m.BytesAB
				}
			}
			if cv.LastTS > m.LastTS {
				m.LastTS = cv.LastTS
			}
		}
	}
	out := make([]*Conv, 0, len(merged))
	for _, cv := range merged {
		out = append(out, cv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstFrame < out[j].FirstFrame })
	return out, nil
}

// Endpoint is one address (and port for TCP/UDP).
type Endpoint struct {
	Addr  dissect.Address
	Port  uint32
	TxP   uint64
	RxP   uint64
	TxB   uint64
	RxB   uint64
	First uint32
	Kind  Kind
}

func (e *Endpoint) Packets() uint64 { return e.TxP + e.RxP }
func (e *Endpoint) Bytes() uint64   { return e.TxB + e.RxB }

// Filter selects the endpoint's packets.
func (e *Endpoint) Filter() string {
	switch e.Kind {
	case Ethernet:
		return fmt.Sprintf("eth.addr == %s", e.Addr)
	case IPv4:
		return fmt.Sprintf("ip.addr == %s", e.Addr)
	case IPv6:
		return fmt.Sprintf("ipv6.addr == %s", e.Addr)
	case TCP:
		return fmt.Sprintf("ip.addr == %s && tcp.port == %d || ipv6.addr == %s && tcp.port == %d", e.Addr, e.Port, e.Addr, e.Port)
	case UDP:
		return fmt.Sprintf("ip.addr == %s && udp.port == %d || ipv6.addr == %s && udp.port == %d", e.Addr, e.Port, e.Addr, e.Port)
	}
	return ""
}

type epKey struct {
	a dissect.Address
	p uint32
}

// Endpoints aggregates the frames (all when nil) by endpoint.
func Endpoints(ctx context.Context, c *store.Capture, frames []uint32, k Kind) ([]*Endpoint, error) {
	if frames == nil {
		frames = engine.AllFrames(c)
	}
	parts := make([]map[epKey]*Endpoint, engine.Workers())
	for i := range parts {
		parts[i] = map[epKey]*Endpoint{}
	}
	err := engine.Each(ctx, c, dissect.Options{Want: make([]bool, dissect.NumFields())}, frames,
		func(w int, num uint32, pi *dissect.PacketInfo) {
			src, dst, sp, dp, ok := addrs(k, pi)
			if !ok {
				return
			}
			add := func(a dissect.Address, p uint32, tx bool) {
				key := epKey{a, p}
				e := parts[w][key]
				if e == nil {
					e = &Endpoint{Addr: a, Port: p, First: num, Kind: k}
					parts[w][key] = e
				}
				if tx {
					e.TxP++
					e.TxB += uint64(pi.Len)
				} else {
					e.RxP++
					e.RxB += uint64(pi.Len)
				}
				if num < e.First {
					e.First = num
				}
			}
			add(src, sp, true)
			add(dst, dp, false)
		})
	if err != nil {
		return nil, err
	}
	merged := map[epKey]*Endpoint{}
	for _, p := range parts {
		for key, e := range p {
			m := merged[key]
			if m == nil {
				merged[key] = e
				continue
			}
			m.TxP, m.RxP, m.TxB, m.RxB = m.TxP+e.TxP, m.RxP+e.RxP, m.TxB+e.TxB, m.RxB+e.RxB
			m.First = min(m.First, e.First)
		}
	}
	out := make([]*Endpoint, 0, len(merged))
	for _, e := range merged {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].First < out[j].First })
	return out, nil
}

// PHS is a node of the protocol hierarchy.
type PHS struct {
	Name     string // filter abbreviation
	Packets  uint64 // packets containing the protocol
	Bytes    uint64
	EndP     uint64 // packets whose innermost protocol is this one
	EndB     uint64
	Children []*PHS
	byName   map[string]*PHS
}

// Hierarchy builds the protocol hierarchy of the frames (all when nil).
func Hierarchy(ctx context.Context, c *store.Capture, frames []uint32) (*PHS, error) {
	if frames == nil {
		frames = engine.AllFrames(c)
	}
	parts := make([]*PHS, engine.Workers())
	for i := range parts {
		parts[i] = &PHS{Name: "frame", byName: map[string]*PHS{}}
	}
	err := engine.Each(ctx, c, dissect.Options{Want: make([]bool, dissect.NumFields())}, frames,
		func(w int, num uint32, pi *dissect.PacketInfo) {
			node := parts[w]
			node.Packets++
			node.Bytes += uint64(pi.Len)
			prev := ""
			for _, p := range pi.Protocols {
				if p == "frame" || p == "ethertype" || p == prev {
					continue
				}
				prev = p
				ch := node.byName[p]
				if ch == nil {
					ch = &PHS{Name: p, byName: map[string]*PHS{}}
					node.byName[p] = ch
					node.Children = append(node.Children, ch)
				}
				ch.Packets++
				ch.Bytes += uint64(pi.Len)
				node = ch
			}
			node.EndP++
			node.EndB += uint64(pi.Len)
		})
	if err != nil {
		return nil, err
	}
	root := parts[0]
	for _, p := range parts[1:] {
		mergePHS(root, p)
	}
	sortPHS(root)
	return root, nil
}

func mergePHS(dst, src *PHS) {
	if dst != src {
		dst.Packets += src.Packets
		dst.Bytes += src.Bytes
		dst.EndP += src.EndP
		dst.EndB += src.EndB
	}
	for _, sc := range src.Children {
		dc := dst.byName[sc.Name]
		if dc == nil {
			dc = &PHS{Name: sc.Name, byName: map[string]*PHS{}}
			dst.byName[sc.Name] = dc
			dst.Children = append(dst.Children, dc)
		}
		mergePHS(dc, sc)
	}
}

func sortPHS(n *PHS) {
	sort.Slice(n.Children, func(i, j int) bool {
		if n.Children[i].Packets != n.Children[j].Packets {
			return n.Children[i].Packets > n.Children[j].Packets
		}
		return n.Children[i].Name < n.Children[j].Name
	})
	for _, c := range n.Children {
		sortPHS(c)
	}
}

// LengthBin is one bucket of the packet length histogram.
type LengthBin struct {
	Label string
	Count uint64
}

var lengthEdges = []int{19, 39, 79, 159, 319, 639, 1279, 2559, 5119}

// Lengths returns Wireshark's packet length buckets.
func Lengths(ctx context.Context, c *store.Capture, frames []uint32) ([]LengthBin, error) {
	if frames == nil {
		frames = engine.AllFrames(c)
	}
	n := len(lengthEdges) + 1
	parts := make([][]uint64, engine.Workers())
	for i := range parts {
		parts[i] = make([]uint64, n)
	}
	err := engine.Each(ctx, c, dissect.Options{Want: make([]bool, dissect.NumFields())}, frames,
		func(w int, num uint32, pi *dissect.PacketInfo) {
			b := 0
			for b < len(lengthEdges) && int(pi.Len) > lengthEdges[b] {
				b++
			}
			parts[w][b]++
		})
	if err != nil {
		return nil, err
	}
	out := make([]LengthBin, n)
	lo := 0
	for i := range out {
		if i < len(lengthEdges) {
			out[i].Label = fmt.Sprintf("%d-%d", lo, lengthEdges[i])
			lo = lengthEdges[i] + 1
		} else {
			out[i].Label = fmt.Sprintf("%d and greater", lo)
		}
		for _, p := range parts {
			out[i].Count += p[i]
		}
	}
	return out, nil
}
