package dissect

import (
	"sync"

	"github.com/poseydon/lazysniffer/internal/pcapio"
)

// ConvType is the kind of a conversation.
type ConvType uint8

const (
	ConvNone ConvType = iota
	ConvEther
	ConvIPv4
	ConvIPv6
	ConvTCP
	ConvUDP
	ConvSCTP
)

func (c ConvType) String() string {
	switch c {
	case ConvEther:
		return "Ethernet"
	case ConvIPv4:
		return "IPv4"
	case ConvIPv6:
		return "IPv6"
	case ConvTCP:
		return "TCP"
	case ConvUDP:
		return "UDP"
	case ConvSCTP:
		return "SCTP"
	}
	return "None"
}

type convKey struct {
	typ    ConvType
	a, b   Address
	pa, pb uint32
}

// Conversation is a bidirectional flow between two endpoints. Endpoint A is
// the one that sent the first frame.
type Conversation struct {
	Type       ConvType
	Index      uint32 // stream index (tcp.stream, udp.stream)
	AddrA      Address
	AddrB      Address
	PortA      uint32
	PortB      uint32
	FirstFrame uint32
	LastFrame  uint32
	FirstTS    int64
	data       map[int]any
}

// Data returns protocol-private conversation data.
func (c *Conversation) Data(p *Proto) any {
	if c == nil || c.data == nil {
		return nil
	}
	return c.data[p.Index]
}

// SetData stores protocol-private conversation data (first pass only).
func (c *Conversation) SetData(p *Proto, v any) {
	if c.data == nil {
		c.data = map[int]any{}
	}
	c.data[p.Index] = v
}

// FromA reports whether a frame from src:sport travels A→B.
func (c *Conversation) FromA(src Address, sport uint32) bool {
	return c.AddrA == src && c.PortA == sport
}

type frameKey struct {
	proto int
	frame uint32
	key   uint32
}

// Session holds capture-wide dissection state. The first pass mutates it
// sequentially; later passes only read.
type Session struct {
	mu         sync.RWMutex
	Interfaces []pcapio.Interface
	// FrameBytes returns the captured bytes of a frame (used to rebuild
	// reassembled data in later passes). Set by the frame store.
	FrameBytes func(num uint32) []byte
	frameData  map[frameKey]any
	convs      map[convKey]*Conversation
	convList   map[ConvType][]*Conversation
	state      map[int]any
}

// ProtoState returns capture-wide protocol state (first pass writes it).
func (s *Session) ProtoState(p *Proto) any { return s.state[p.Index] }

// SetProtoState stores capture-wide protocol state.
func (s *Session) SetProtoState(p *Proto, v any) { s.state[p.Index] = v }

// NewSession creates dissection state for one capture.
func NewSession(ifaces []pcapio.Interface) *Session {
	return &Session{
		Interfaces: ifaces,
		frameData:  map[frameKey]any{},
		convs:      map[convKey]*Conversation{},
		convList:   map[ConvType][]*Conversation{},
		state:      map[int]any{},
	}
}

// SetFrameData stores per-frame protocol data (first pass only).
func (s *Session) SetFrameData(p *Proto, frame, key uint32, v any) {
	s.frameData[frameKey{p.Index, frame, key}] = v
}

// FrameData returns per-frame protocol data.
func (s *Session) FrameData(p *Proto, frame, key uint32) any {
	return s.frameData[frameKey{p.Index, frame, key}]
}

func normKey(typ ConvType, a, b Address, pa, pb uint32) convKey {
	c := a.Compare(b)
	if c > 0 || (c == 0 && pa > pb) {
		a, b, pa, pb = b, a, pb, pa
	}
	return convKey{typ, a, b, pa, pb}
}

// FindConversation returns an existing conversation.
func (s *Session) FindConversation(typ ConvType, src, dst Address, sport, dport uint32) *Conversation {
	return s.convs[normKey(typ, src, dst, sport, dport)]
}

// Conversation finds or (in the first pass) creates a conversation.
func (s *Session) Conversation(pi *PacketInfo, typ ConvType, src, dst Address, sport, dport uint32) *Conversation {
	k := normKey(typ, src, dst, sport, dport)
	c := s.convs[k]
	if c == nil && !pi.Visited {
		c = &Conversation{
			Type: typ, Index: uint32(len(s.convList[typ])),
			AddrA: src, AddrB: dst, PortA: sport, PortB: dport,
			FirstFrame: pi.Num, FirstTS: pi.TS,
		}
		s.convs[k] = c
		s.convList[typ] = append(s.convList[typ], c)
	}
	if c != nil && !pi.Visited && pi.Num > c.LastFrame {
		c.LastFrame = pi.Num
	}
	return c
}

// NewConversationAfter replaces a conversation (e.g. TCP port reuse after
// FIN/RST): the next lookup with the same endpoints returns the new one.
func (s *Session) NewConversationAfter(pi *PacketInfo, old *Conversation) *Conversation {
	k := normKey(old.Type, old.AddrA, old.AddrB, old.PortA, old.PortB)
	c := &Conversation{
		Type: old.Type, Index: uint32(len(s.convList[old.Type])),
		AddrA: pi.Src, AddrB: pi.Dst, PortA: pi.SrcPort, PortB: pi.DstPort,
		FirstFrame: pi.Num, LastFrame: pi.Num, FirstTS: pi.TS,
	}
	s.convs[k] = c
	s.convList[old.Type] = append(s.convList[old.Type], c)
	return c
}

// Conversations returns conversations of a type in creation order.
func (s *Session) Conversations(typ ConvType) []*Conversation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*Conversation(nil), s.convList[typ]...)
}

// FrameInput is everything the frame dissector needs about one packet.
type FrameInput struct {
	Num      uint32
	TS       int64
	RelTS    int64
	DeltaTS  int64
	CapLen   uint32
	Len      uint32
	Iface    uint32
	EPBFlags uint32
	Comments []string
	Marked   bool
	Ignored  bool
	Data     []byte
}

// Options control what a dissection produces.
type Options struct {
	Full    bool   // build the displayable tree
	Want    []bool // fields to record (nil = all)
	Columns bool   // build column text
}

var frameHandle *Handle

// SetFrameHandle installs the top-level "frame" dissector.
func SetFrameHandle(h *Handle) { frameHandle = h }

// Worker dissects frames and reuses its buffers between calls. A worker is
// not safe for concurrent use; create one per goroutine.
type Worker struct {
	s    *Session
	opt  Options
	pi   PacketInfo
	tree *Tree
}

// NewWorker creates a worker with fixed options.
func (s *Session) NewWorker(opt Options) *Worker {
	return &Worker{s: s, opt: opt, tree: NewTree(opt.Full, opt.Want)}
}

// FirstPass dissects a frame in the sequential first pass, updating state.
func (w *Worker) FirstPass(fi *FrameInput) *PacketInfo {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return w.run(fi, false)
}

// Dissect re-dissects an already-visited frame using stored state.
func (w *Worker) Dissect(fi *FrameInput) *PacketInfo {
	w.s.mu.RLock()
	defer w.s.mu.RUnlock()
	return w.run(fi, true)
}

func (w *Worker) run(fi *FrameInput, visited bool) *PacketInfo {
	t := w.tree
	if w.opt.Full {
		// Full trees are handed to the UI and must not be reused.
		t = NewTree(true, w.opt.Want)
	} else {
		t.Reset()
	}
	pi := &w.pi
	if w.opt.Full {
		pi = &PacketInfo{}
	} else {
		protos := pi.Protocols[:0]
		experts := pi.Experts[:0]
		sources := pi.Sources[:0]
		scratch := pi.scratch[:0]
		*pi = PacketInfo{Protocols: protos, Experts: experts, Sources: sources, scratch: scratch}
	}
	pi.Sess = w.s
	pi.Tree = t
	t.PI = pi
	pi.Num, pi.TS, pi.RelTS, pi.DeltaTS = fi.Num, fi.TS, fi.RelTS, fi.DeltaTS
	pi.CapLen, pi.Len, pi.Iface, pi.EPBFlags = fi.CapLen, fi.Len, fi.Iface, fi.EPBFlags
	pi.Comments, pi.Marked, pi.Ignored = fi.Comments, fi.Marked, fi.Ignored
	pi.Visited = visited
	pi.wantCols = w.opt.Columns
	pi.PID = -1
	if int(fi.Iface) < len(w.s.Interfaces) {
		pi.LinkType = w.s.Interfaces[fi.Iface].LinkType
	}
	pi.Sources = append(pi.Sources, DataSource{Name: "Frame", Data: fi.Data})
	tvb := NewTvb(fi.Data, int(fi.Len), 0)
	if frameHandle != nil {
		pi.Call(frameHandle, tvb, &t.Root)
	}
	return pi
}

// FrameTable stores fixed-size per-frame values densely, indexed by frame
// number, in fixed-size pages (no copying or doubling as captures grow).
type FrameTable[T any] struct {
	pages [][]T
	set   [][]bool
}

const framePageBits = 12

// Put stores v for frame num (first pass only).
func (t *FrameTable[T]) Put(num uint32, v T) {
	p := int(num >> framePageBits)
	for len(t.pages) <= p {
		t.pages = append(t.pages, make([]T, 1<<framePageBits))
		t.set = append(t.set, make([]bool, 1<<framePageBits))
	}
	i := num & (1<<framePageBits - 1)
	t.pages[p][i], t.set[p][i] = v, true
}

// Get returns the value for frame num.
func (t *FrameTable[T]) Get(num uint32) (T, bool) {
	p := int(num >> framePageBits)
	i := num & (1<<framePageBits - 1)
	if p < len(t.pages) && t.set[p][i] {
		return t.pages[p][i], true
	}
	var zero T
	return zero, false
}

// Table returns the per-frame table a protocol keeps in the session,
// creating it on first use.
func SessionTable[T any](s *Session, p *Proto) *FrameTable[T] {
	if t, ok := s.ProtoState(p).(*FrameTable[T]); ok {
		return t
	}
	t := &FrameTable[T]{}
	s.SetProtoState(p, t)
	return t
}
