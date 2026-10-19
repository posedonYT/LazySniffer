// Package pcaptools implements the capture file utilities of the Wireshark
// suite: capinfos, mergecap, editcap, reordercap and text2pcap.
package pcaptools

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/poseydon/lazysniffer/internal/pcapio"
)

// Packet is a packet read into memory with its interface description.
type Packet struct {
	Rec  pcapio.Record
	Data []byte
	If   pcapio.Interface
}

// Info is the summary printed by `lazysniffer info`.
type Info struct {
	Path        string
	Format      pcapio.Format
	Encap       []string
	Packets     int
	DataBytes   uint64
	First, Last int64
	SHA256      string
	Comments    []string
	Interfaces  []pcapio.Interface
	Size        int64
}

// Duration in seconds.
func (i Info) Duration() float64 { return float64(i.Last-i.First) / 1e9 }

// Summarize reads a capture file like capinfos.
func Summarize(path string) (*Info, error) {
	f, err := pcapio.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	in := &Info{Path: path, Format: f.Format, Comments: f.Section.Comments, Interfaces: f.Interfaces, Size: f.Size()}
	seen := map[string]bool{}
	for {
		rec, err := f.Next()
		if err != nil {
			break
		}
		in.Packets++
		in.DataBytes += uint64(rec.OrigLen)
		if in.Packets == 1 || rec.TS < in.First {
			in.First = rec.TS
		}
		in.Last = max(in.Last, rec.TS)
		if int(rec.Iface) < len(f.Interfaces) {
			if e := f.Interfaces[rec.Iface].LinkType.String(); !seen[e] {
				seen[e] = true
				in.Encap = append(in.Encap, e)
			}
		}
	}
	if b, err := os.ReadFile(path); err == nil {
		h := sha256.Sum256(b)
		in.SHA256 = hex.EncodeToString(h[:])
	}
	return in, nil
}

// Read loads all packets of a file.
func Read(path string) ([]Packet, *pcapio.File, error) {
	f, err := pcapio.Open(path)
	if err != nil {
		return nil, nil, err
	}
	var out []Packet
	for {
		rec, err := f.Next()
		if err != nil {
			break
		}
		p := Packet{Rec: rec, Data: append([]byte(nil), f.Data(rec.DataOff, rec.CapLen)...)}
		if int(rec.Iface) < len(f.Interfaces) {
			p.If = f.Interfaces[rec.Iface]
		}
		out = append(out, p)
	}
	return out, f, nil
}

// WriteOptions control the output of Write.
type WriteOptions struct {
	Format  pcapio.Format // pcapng (default) or pcap
	Secrets []pcapio.Secrets
	Section pcapio.SectionInfo
}

type writer interface {
	AddInterface(pcapio.Interface) (uint32, error)
	WritePacket(pcapio.Record, []byte) error
	WriteSecrets(pcapio.Secrets) error
	Flush() error
}

// Write writes packets to w. Interfaces are deduplicated by description.
func Write(w io.Writer, pkts []Packet, o WriteOptions) error {
	var wr writer
	if o.Format == pcapio.FormatPcap {
		wr = pcapio.NewPcapWriter(w, false)
	} else {
		nw, err := pcapio.NewNgWriter(w, o.Section)
		if err != nil {
			return err
		}
		wr = nw
		for _, s := range o.Secrets {
			if err := nw.WriteSecrets(s); err != nil {
				return err
			}
		}
	}
	ifIDs := map[string]uint32{}
	for _, p := range pkts {
		key := fmt.Sprintf("%d|%d|%s|%s", p.If.LinkType, p.If.SnapLen, p.If.Name, p.If.Description)
		id, ok := ifIDs[key]
		if !ok {
			var err error
			ifc := p.If
			if ifc.SnapLen == 0 {
				ifc.SnapLen = 262144
			}
			ifc.FCSLen = -1
			if id, err = wr.AddInterface(ifc); err != nil {
				return err
			}
			ifIDs[key] = id
		}
		rec := p.Rec
		rec.Iface = id
		if err := wr.WritePacket(rec, p.Data); err != nil {
			return err
		}
	}
	return wr.Flush()
}

// Merge combines files chronologically (or appends them in order).
func Merge(paths []string, appendMode bool) ([]Packet, []pcapio.Secrets, error) {
	var all []Packet
	var secrets []pcapio.Secrets
	for _, p := range paths {
		pk, f, err := Read(p)
		if err != nil {
			return nil, nil, err
		}
		secrets = append(secrets, f.Secrets...)
		f.Close()
		all = append(all, pk...)
	}
	if !appendMode {
		sort.SliceStable(all, func(i, j int) bool { return all[i].Rec.TS < all[j].Rec.TS })
	}
	return all, secrets, nil
}

// Reorder sorts packets by timestamp.
func Reorder(pkts []Packet) []Packet {
	out := append([]Packet(nil), pkts...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Rec.TS < out[j].Rec.TS })
	return out
}

// EditOptions are the editcap operations.
type EditOptions struct {
	Keep      []Range // packet ranges to keep (1-based); empty keeps all
	Delete    []Range // packet ranges to drop
	SnapLen   int
	Dedup     int // window of previous packets to compare (0 = off)
	TimeShift int64
	StripComm bool
}

// Range is an inclusive packet range; To == 0 means "to the end".
type Range struct{ From, To int }

// ParseRanges parses "1-10,15,20-" (editcap syntax).
func ParseRanges(s string) ([]Range, error) {
	var out []Range
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, b, isRange := strings.Cut(part, "-")
		from, err := strconv.Atoi(a)
		if err != nil || from < 1 {
			return nil, fmt.Errorf("bad packet range %q", part)
		}
		r := Range{From: from, To: from}
		if isRange {
			r.To = 0
			if b != "" {
				if r.To, err = strconv.Atoi(b); err != nil || r.To < from {
					return nil, fmt.Errorf("bad packet range %q", part)
				}
			}
		}
		out = append(out, r)
	}
	return out, nil
}

func (r Range) has(n int) bool { return n >= r.From && (r.To == 0 || n <= r.To) }

func inRanges(rs []Range, n int) bool {
	for _, r := range rs {
		if r.has(n) {
			return true
		}
	}
	return false
}

// Edit applies the operations in editcap's order.
func Edit(pkts []Packet, o EditOptions) []Packet {
	var out []Packet
	seen := map[[32]byte]int{}
	for i, p := range pkts {
		n := i + 1
		if len(o.Keep) > 0 && !inRanges(o.Keep, n) {
			continue
		}
		if inRanges(o.Delete, n) {
			continue
		}
		if o.Dedup > 0 {
			h := sha256.Sum256(p.Data)
			if last, ok := seen[h]; ok && len(out)-last <= o.Dedup {
				continue
			}
			seen[h] = len(out)
		}
		if o.SnapLen > 0 && len(p.Data) > o.SnapLen {
			p.Data = p.Data[:o.SnapLen]
			p.Rec.CapLen = uint32(o.SnapLen)
		}
		p.Rec.TS += o.TimeShift
		if o.StripComm {
			p.Rec.Comments = nil
		}
		out = append(out, p)
	}
	return out
}

// Split cuts pkts into chunks of n packets, or of d duration when d > 0.
func Split(pkts []Packet, n int, d time.Duration) [][]Packet {
	var out [][]Packet
	var cur []Packet
	var start int64
	for _, p := range pkts {
		if len(cur) > 0 && ((n > 0 && len(cur) >= n) || (d > 0 && p.Rec.TS-start >= int64(d))) {
			out = append(out, cur)
			cur = nil
		}
		if len(cur) == 0 {
			start = p.Rec.TS
		}
		cur = append(cur, p)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// Text2Pcap converts a hex dump (offset hex… lines, blank line between
// packets) into packets of the given link type. Lines starting with '#' are
// comments; an optional leading timestamp "HH:MM:SS.fff " per packet is
// honoured when it precedes the first offset of a packet.
func Text2Pcap(r io.Reader, link pcapio.LinkType, base time.Time) ([]Packet, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, 1<<20)
	var pkts []Packet
	var cur []byte
	var started bool
	ts := base.UnixNano()
	flush := func() {
		if started {
			pkts = append(pkts, Packet{Rec: pcapio.Record{TS: ts, CapLen: uint32(len(cur)), OrigLen: uint32(len(cur))}, Data: cur,
				If: pcapio.Interface{LinkType: link, SnapLen: 262144, Name: "text2pcap"}})
			ts += 1000 // one microsecond apart, like text2pcap without -t
		}
		cur, started = nil, false
	}
	expect := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			flush()
			expect = 0
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		off, err := strconv.ParseUint(strings.TrimSuffix(fields[0], ":"), 16, 32)
		if err != nil {
			return nil, fmt.Errorf("bad offset %q", fields[0])
		}
		if int(off) == 0 && started && expect != 0 {
			flush()
			expect = 0
		}
		started = true
		for _, f := range fields[1:] {
			if len(f) != 2 {
				break // the ASCII column
			}
			b, err := strconv.ParseUint(f, 16, 8)
			if err != nil {
				break
			}
			cur = append(cur, byte(b))
		}
		expect = len(cur)
	}
	flush()
	return pkts, sc.Err()
}
