package dissect

import (
	"bytes"
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/poseydon/lazysniffer/internal/pcapio"
)

// AddrType is the kind of an Address.
type AddrType uint8

const (
	AddrNone AddrType = iota
	AddrEther
	AddrIPv4
	AddrIPv6
	AddrString
)

// Address is a comparable network or link-layer address.
type Address struct {
	Type AddrType
	n    uint8
	b    [16]byte
	s    string
}

func EtherAddr(b []byte) Address {
	a := Address{Type: AddrEther, n: 6}
	copy(a.b[:], b)
	return a
}

func IPv4Addr(u uint32) Address {
	a := Address{Type: AddrIPv4, n: 4}
	a.b[0], a.b[1], a.b[2], a.b[3] = byte(u>>24), byte(u>>16), byte(u>>8), byte(u)
	return a
}

func IPv6Addr(b []byte) Address {
	a := Address{Type: AddrIPv6, n: 16}
	copy(a.b[:], b)
	return a
}

func StringAddr(s string) Address { return Address{Type: AddrString, s: s} }

// Bytes returns the raw address bytes.
func (a Address) Bytes() []byte { return a.b[:a.n] }

// IsZero reports whether the address is unset.
func (a Address) IsZero() bool { return a.Type == AddrNone }

func (a Address) String() string {
	switch a.Type {
	case AddrEther:
		return FormatEther(a.b[:6])
	case AddrIPv4:
		return FormatIPv4(uint32(a.b[0])<<24 | uint32(a.b[1])<<16 | uint32(a.b[2])<<8 | uint32(a.b[3]))
	case AddrIPv6:
		return FormatIPv6(a.b[:16])
	case AddrString:
		return a.s
	}
	return ""
}

// Compare orders addresses (type first, then bytes).
func (a Address) Compare(b Address) int {
	if a.Type != b.Type {
		if a.Type < b.Type {
			return -1
		}
		return 1
	}
	if a.Type == AddrString {
		return strings.Compare(a.s, b.s)
	}
	return bytes.Compare(a.b[:a.n], b.b[:b.n])
}

// PortType is the transport of SrcPort/DstPort.
type PortType uint8

const (
	PortNone PortType = iota
	PortTCP
	PortUDP
	PortSCTP
)

// DataSource is a buffer shown as a tab in the bytes pane.
type DataSource struct {
	Name string
	Data []byte
}

// PacketInfo carries per-packet dissection state ("pinfo").
type PacketInfo struct {
	Sess *Session
	Tree *Tree

	Num      uint32
	TS       int64
	RelTS    int64
	DeltaTS  int64
	CapLen   uint32
	Len      uint32
	Iface    uint32
	LinkType pcapio.LinkType
	EPBFlags uint32
	Comments []string
	Marked   bool
	Ignored  bool
	Visited  bool // false during the first sequential pass

	Sources []DataSource

	DLSrc, DLDst   Address
	NetSrc, NetDst Address
	Src, Dst       Address
	PortType       PortType
	SrcPort        uint32
	DstPort        uint32
	MatchUint      uint64 // key that selected the current dissector

	Protocols []string
	Experts   []ExpertEntry
	// MaxSeverity is the highest expert severity in the frame.
	MaxSeverity Severity

	// Process attribution (PKTAP on macOS, socket table on Linux).
	PID      int32
	ProcName string

	// Conv is the transport conversation of the frame, if any.
	Conv *Conversation
	// InErrorPkt is set while dissecting a packet embedded in an ICMP
	// error; dissectors must not update columns, addresses or state.
	InErrorPkt bool

	scratch []scratchEntry

	// Desegmentation request from a TCP payload dissector.
	desegOff    int
	desegMore   int
	desegSet    bool
	desegHandle *Handle
	curHandle   *Handle

	wantCols  bool
	protoCol  string
	info      strings.Builder
	infoFence int
	depth     int
	cur       *Proto
}

type scratchEntry struct {
	p *Proto
	v any
}

// SetScratch stores per-packet data for p, visible to later dissectors of
// the same packet (e.g. TCP sequence info for its payload dissectors).
func (pi *PacketInfo) SetScratch(p *Proto, v any) {
	for i := range pi.scratch {
		if pi.scratch[i].p == p {
			pi.scratch[i].v = v
			return
		}
	}
	pi.scratch = append(pi.scratch, scratchEntry{p, v})
}

// Scratch returns per-packet data stored with SetScratch.
func (pi *PacketInfo) Scratch(p *Proto) any {
	for i := range pi.scratch {
		if pi.scratch[i].p == p {
			return pi.scratch[i].v
		}
	}
	return nil
}

// DesegmentOneMore asks for one more segment when the needed length is unknown.
const DesegmentOneMore = -1

// Desegment tells the transport that the data from offset on is an
// incomplete PDU needing more bytes (or DesegmentOneMore).
func (pi *PacketInfo) Desegment(offset, more int) {
	pi.desegOff, pi.desegMore, pi.desegSet = offset, more, true
	pi.desegHandle = pi.curHandle
}

// TakeDesegment returns and clears a pending desegmentation request.
func (pi *PacketInfo) TakeDesegment() (offset, more int, h *Handle, ok bool) {
	offset, more, h, ok = pi.desegOff, pi.desegMore, pi.desegHandle, pi.desegSet
	pi.desegSet, pi.desegHandle = false, nil
	return
}

// WantColumns reports whether column text is being built.
func (pi *PacketInfo) WantColumns() bool { return pi.wantCols }

// SetProtocol sets the Protocol column.
func (pi *PacketInfo) SetProtocol(s string) {
	if pi.wantCols {
		pi.protoCol = s
	}
}

// Protocol is the Protocol column text.
func (pi *PacketInfo) Protocol() string { return pi.protoCol }

// Info is the Info column text.
func (pi *PacketInfo) Info() string { return pi.info.String() }

// SetInfo replaces the Info column text after the fence.
func (pi *PacketInfo) SetInfo(s string) {
	if !pi.wantCols {
		return
	}
	pi.ClearInfo()
	pi.info.WriteString(s)
}

// SetInfof is SetInfo with formatting.
func (pi *PacketInfo) SetInfof(format string, args ...any) {
	if pi.wantCols {
		pi.SetInfo(fmt.Sprintf(format, args...))
	}
}

// ClearInfo erases the Info column text after the fence.
func (pi *PacketInfo) ClearInfo() {
	if !pi.wantCols {
		return
	}
	s := pi.info.String()
	if pi.infoFence < len(s) {
		pi.info.Reset()
		pi.info.WriteString(s[:pi.infoFence])
	}
}

// AppendInfo appends formatted text to the Info column.
func (pi *PacketInfo) AppendInfo(format string, args ...any) {
	if pi.wantCols {
		if len(args) == 0 {
			pi.info.WriteString(format)
		} else {
			fmt.Fprintf(&pi.info, format, args...)
		}
	}
}

// AppendInfoSep appends text preceded by sep unless the column is empty.
func (pi *PacketInfo) AppendInfoSep(sep, s string) {
	if !pi.wantCols {
		return
	}
	if pi.info.Len() > 0 {
		pi.info.WriteString(sep)
	}
	pi.info.WriteString(s)
}

// FenceInfo protects the current Info text from later SetInfo/ClearInfo.
func (pi *PacketInfo) FenceInfo() {
	if pi.wantCols {
		pi.infoFence = pi.info.Len()
	}
}

// AddSource registers a new data source (reassembled, decrypted, ...) and
// returns a view of it.
func (pi *PacketInfo) AddSource(name string, data []byte) *Tvb {
	pi.Sources = append(pi.Sources, DataSource{Name: name, Data: data})
	return NewTvb(data, len(data), uint8(len(pi.Sources)-1))
}

// SetAddresses records network-layer addresses and makes them the
// Source/Destination columns.
func (pi *PacketInfo) SetNetAddrs(src, dst Address) {
	pi.NetSrc, pi.NetDst = src, dst
	pi.Src, pi.Dst = src, dst
}

// SetDLAddrs records link-layer addresses.
func (pi *PacketInfo) SetDLAddrs(src, dst Address) {
	pi.DLSrc, pi.DLDst = src, dst
	pi.Src, pi.Dst = src, dst
}

// Call runs a dissector, recovering from bounds errors and dissector bugs.
// It returns the number of bytes consumed (0 if the dissector rejected the data).
func (pi *PacketInfo) Call(h *Handle, tvb *Tvb, tree *Node) (consumed int) {
	if h == nil || (h.Proto != nil && !h.Proto.Enabled) {
		return 0
	}
	if pi.depth > 64 {
		return 0
	}
	pi.depth++
	prev, prevH := pi.cur, pi.curHandle
	pi.cur, pi.curHandle = h.Proto, h
	defer func() {
		pi.depth--
		if r := recover(); r != nil {
			pi.exception(r, tree)
			consumed = tvb.Len()
		}
		pi.cur, pi.curHandle = prev, prevH
	}()
	return h.Fn(tvb, pi, tree)
}

// StrictBugs makes dissector bugs (panics other than bounds errors) crash
// instead of being shown in the tree. Tests and fuzzers set it.
var StrictBugs = false

func (pi *PacketInfo) exception(r any, tree *Node) {
	name := "unknown"
	if pi.cur != nil {
		name = pi.cur.Short
	}
	if be, ok := r.(BoundsError); ok {
		if be.Short {
			n := tree.AddProtocol(shortProto, nil, 0, 0)
			n.SetText("[Packet size limited during capture: %s truncated]", name)
			pi.AppendInfo("[Packet size limited during capture]")
			return
		}
		n := tree.AddProtocol(malformedProto, nil, 0, 0)
		n.SetText("[Malformed Packet: %s]", name)
		n.AddExpert(eiMalformed, "")
		pi.AppendInfo("[Malformed Packet]")
		return
	}
	if StrictBugs {
		panic(r)
	}
	n := tree.AddProtocol(bugProto, nil, 0, 0)
	msg := fmt.Sprint(r)
	n.SetText("[Dissector bug, protocol %s: %s]", name, msg)
	n.AddExpert(eiDissectorBug, "Dissector bug, protocol %s: %s", name, msg)
	if tree.Tree().full {
		n.AddText(nil, 0, 0, "%s", strings.ReplaceAll(string(debug.Stack()), "\t", "  "))
	}
	pi.AppendInfo("[Dissector bug, protocol %s]", name)
}

// PortString formats a port for Info columns.
func PortString(p uint32) string { return strconv.FormatUint(uint64(p), 10) }

// Snapshot is a restore point for the output of one dissector call, used
// when a dissector asks for more data and its partial output must be
// discarded (Wireshark shows such frames as "segment of a reassembled PDU").
type Snapshot struct {
	vals, protos, sources, experts int
	info                           string
	fence                          int
	proto                          string
	parent                         *Node
	last                           *Node
	maxSev                         Severity
}

// Snapshot remembers the state before calling a dissector with tree
// parent.
func (pi *PacketInfo) Snapshot(parent *Node) Snapshot {
	s := Snapshot{protos: len(pi.Protocols), sources: len(pi.Sources), experts: len(pi.Experts), fence: pi.infoFence, proto: pi.protoCol,
		info: pi.info.String(), parent: parent, last: parent.Last, maxSev: pi.MaxSeverity}
	if pi.Tree != nil {
		s.vals = len(pi.Tree.Vals)
	}
	return s
}

// Rollback discards everything the dissector added since the snapshot.
func (pi *PacketInfo) Rollback(s Snapshot) {
	if pi.Tree != nil && len(pi.Tree.Vals) > s.vals {
		pi.Tree.Vals = pi.Tree.Vals[:s.vals]
	}
	pi.Protocols = pi.Protocols[:min(len(pi.Protocols), s.protos)]
	pi.Sources = pi.Sources[:min(len(pi.Sources), s.sources)]
	pi.Experts = pi.Experts[:min(len(pi.Experts), s.experts)]
	pi.MaxSeverity = s.maxSev
	if s.parent != nil {
		s.parent.Last = s.last
		if s.last != nil {
			s.last.Next = nil
		} else {
			s.parent.First = nil
		}
	}
	if pi.wantCols {
		pi.info.Reset()
		pi.info.WriteString(s.info)
		pi.infoFence = s.fence
		pi.protoCol = s.proto
	}
}
