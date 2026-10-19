// Package columns builds packet-list rows: column definitions, time formats
// and per-frame cell text.
package columns

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/store"
)

// Kind is a column type.
type Kind uint8

const (
	KindNumber Kind = iota
	KindTime
	KindSource
	KindDestination
	KindProtocol
	KindLength
	KindInfo
	KindCustom
	KindProcess
	KindSrcPort
	KindDstPort
	KindInterface
	KindDelta
	KindCapLen
)

var kindNames = map[Kind]string{
	KindNumber: "number", KindTime: "time", KindSource: "source", KindDestination: "destination",
	KindProtocol: "protocol", KindLength: "length", KindInfo: "info", KindCustom: "custom",
	KindProcess: "process", KindSrcPort: "src_port", KindDstPort: "dst_port",
	KindInterface: "interface", KindDelta: "delta", KindCapLen: "cap_len",
}

func (k Kind) String() string { return kindNames[k] }

// ParseKind converts a config name to a Kind.
func ParseKind(s string) (Kind, bool) {
	for k, n := range kindNames {
		if n == s {
			return k, true
		}
	}
	return 0, false
}

// Column describes one packet-list column.
type Column struct {
	Title string `yaml:"title"`
	Kind  Kind   `yaml:"-"`
	Type  string `yaml:"type"`
	Field string `yaml:"field,omitempty"` // display filter field for custom columns
	Width int    `yaml:"width,omitempty"` // 0 = automatic
	Hide  bool   `yaml:"hidden,omitempty"`
	Right bool   `yaml:"-"`
}

// Defaults returns Wireshark's default column set plus Process.
func Defaults() []Column {
	return []Column{
		{Title: "No.", Kind: KindNumber, Right: true},
		{Title: "Time", Kind: KindTime, Right: true},
		{Title: "Source", Kind: KindSource},
		{Title: "Destination", Kind: KindDestination},
		{Title: "Protocol", Kind: KindProtocol},
		{Title: "Length", Kind: KindLength, Right: true},
		{Title: "Process", Kind: KindProcess, Hide: true},
		{Title: "Info", Kind: KindInfo},
	}
}

// TimeFormat selects how the Time column is rendered.
type TimeFormat uint8

const (
	TimeRelative TimeFormat = iota
	TimeAbsolute
	TimeAbsoluteDate
	TimeUTC
	TimeUTCDate
	TimeEpoch
	TimeDeltaCaptured
	TimeDeltaDisplayed
)

// TimeFormats lists formats with menu titles in Wireshark's order.
var TimeFormats = []struct {
	F     TimeFormat
	Title string
}{
	{TimeAbsoluteDate, "Date and Time of Day (1970-01-01 01:02:03.123456)"},
	{TimeAbsolute, "Time of Day (01:02:03.123456)"},
	{TimeEpoch, "Seconds Since Epoch (1970-01-01)"},
	{TimeRelative, "Seconds Since First Captured Packet"},
	{TimeDeltaCaptured, "Seconds Since Previous Captured Packet"},
	{TimeDeltaDisplayed, "Seconds Since Previous Displayed Packet"},
	{TimeUTCDate, "UTC Date and Time of Day (1970-01-01 01:02:03.123456)"},
	{TimeUTC, "UTC Time of Day (01:02:03.123456)"},
}

// Row is the rendered packet-list row of a frame.
type Row struct {
	Num   uint32
	Cells []string
	// Color is the index of the matching coloring rule, or -1.
	Color int
	Sev   dissect.Severity
	Flags uint16
}

// Builder renders rows. It is not safe for concurrent use.
type Builder struct {
	Cols      []Column
	Time      TimeFormat
	Precision int // digits after the decimal point
	cap       *store.Capture
	worker    *dissect.Worker
	custom    []*dissect.FieldDef
	// Colorize returns the coloring rule index for a dissected frame.
	Colorize func(pi *dissect.PacketInfo) int
	// ResolveAddr renders Source/Destination addresses.
	ResolveAddr func(dissect.Address) string
	// Extra fields to record (for coloring rules).
	Extra []*dissect.FieldDef
	// Process attributes a frame to a local process when the capture has no
	// per-packet process information (Linux socket sampling).
	Process func(pi *dissect.PacketInfo) string
}

// NewBuilder creates a row builder for a capture.
func NewBuilder(c *store.Capture, cols []Column) *Builder {
	b := &Builder{Cols: cols, cap: c, Precision: 6}
	b.Rebuild()
	return b
}

// Rebuild recomputes the set of recorded fields after columns or Extra change.
func (b *Builder) Rebuild() {
	want := make([]bool, dissect.NumFields())
	b.custom = make([]*dissect.FieldDef, len(b.Cols))
	for i, c := range b.Cols {
		if c.Kind == KindCustom {
			for _, name := range strings.Split(c.Field, "||") {
				if f := dissect.LookupField(strings.TrimSpace(name)); f != nil {
					want[f.ID] = true
					if b.custom[i] == nil {
						b.custom[i] = f
					}
				}
			}
		}
	}
	for _, f := range b.Extra {
		if int(f.ID) < len(want) {
			want[f.ID] = true
		}
	}
	b.worker = b.cap.Session().NewWorker(dissect.Options{Columns: true, Want: want})
}

// Row renders frame num. prevDisplayed is the previous displayed frame (for
// the "since previous displayed" time format), 0 if none.
func (b *Builder) Row(num, prevDisplayed uint32) Row {
	fi := b.cap.Input(num)
	if fi == nil {
		return Row{Num: num, Color: -1}
	}
	pi := b.worker.Dissect(fi)
	m := b.cap.Frame(num)
	row := Row{Num: num, Cells: make([]string, len(b.Cols)), Color: -1, Sev: pi.MaxSeverity, Flags: m.Flags}
	if b.Colorize != nil {
		row.Color = b.Colorize(pi)
	}
	for i, c := range b.Cols {
		row.Cells[i] = b.cell(i, c, pi, fi, m, prevDisplayed)
	}
	return row
}

func (b *Builder) addr(a dissect.Address) string {
	if b.ResolveAddr != nil {
		return b.ResolveAddr(a)
	}
	return a.String()
}

func (b *Builder) cell(i int, c Column, pi *dissect.PacketInfo, fi *dissect.FrameInput, m store.FrameMeta, prev uint32) string {
	switch c.Kind {
	case KindNumber:
		return strconv.FormatUint(uint64(fi.Num), 10)
	case KindTime:
		if m.Flags&store.FlagTimeRef != 0 {
			return "*REF*"
		}
		return b.FormatTime(fi, prev)
	case KindSource:
		return b.addr(pi.Src)
	case KindDestination:
		return b.addr(pi.Dst)
	case KindProtocol:
		return pi.Protocol()
	case KindLength:
		return strconv.FormatUint(uint64(fi.Len), 10)
	case KindCapLen:
		return strconv.FormatUint(uint64(fi.CapLen), 10)
	case KindInfo:
		return pi.Info()
	case KindProcess:
		if pi.ProcName == "" && b.Process != nil {
			return b.Process(pi)
		}
		return pi.ProcName
	case KindSrcPort:
		if pi.PortType == dissect.PortNone {
			return ""
		}
		return strconv.FormatUint(uint64(pi.SrcPort), 10)
	case KindDstPort:
		if pi.PortType == dissect.PortNone {
			return ""
		}
		return strconv.FormatUint(uint64(pi.DstPort), 10)
	case KindInterface:
		ifs := b.cap.Session().Interfaces
		if int(fi.Iface) < len(ifs) && ifs[fi.Iface].Name != "" {
			return ifs[fi.Iface].Name
		}
		return strconv.FormatUint(uint64(fi.Iface), 10)
	case KindDelta:
		return formatSeconds(fi.DeltaTS, b.Precision)
	case KindCustom:
		return b.customCell(c, pi)
	}
	return ""
}

func (b *Builder) customCell(c Column, pi *dissect.PacketInfo) string {
	var parts []string
	for _, name := range strings.Split(c.Field, "||") {
		f := dissect.LookupField(strings.TrimSpace(name))
		if f == nil {
			continue
		}
		for _, v := range pi.Tree.Values(f) {
			s := f.Display(v.V)
			if f.Type == dissect.FtProtocol || f.Type == dissect.FtNone {
				s = f.Name
			}
			if f.VS != nil && f.Type.IsInteger() {
				if n, ok := f.VS[v.V.U]; ok {
					s = n
				}
			}
			parts = append(parts, s)
		}
		if len(parts) > 0 {
			break
		}
	}
	return strings.Join(parts, ",")
}

// FormatTime renders the frame time in the builder's format.
func (b *Builder) FormatTime(fi *dissect.FrameInput, prevDisplayed uint32) string {
	p := b.Precision
	switch b.Time {
	case TimeAbsolute:
		return formatClock(time.Unix(0, fi.TS), "15:04:05", p)
	case TimeAbsoluteDate:
		return formatClock(time.Unix(0, fi.TS), "2006-01-02 15:04:05", p)
	case TimeUTC:
		return formatClock(time.Unix(0, fi.TS).UTC(), "15:04:05", p)
	case TimeUTCDate:
		return formatClock(time.Unix(0, fi.TS).UTC(), "2006-01-02 15:04:05", p)
	case TimeEpoch:
		return formatSeconds(fi.TS, p)
	case TimeDeltaCaptured:
		return formatSeconds(fi.DeltaTS, p)
	case TimeDeltaDisplayed:
		if prevDisplayed == 0 {
			return formatSeconds(0, p)
		}
		return formatSeconds(fi.TS-b.cap.Frame(prevDisplayed).TS, p)
	}
	return formatSeconds(fi.RelTS, p)
}

func formatClock(t time.Time, layout string, prec int) string {
	s := t.Format(layout)
	if prec > 0 {
		frac := fmt.Sprintf("%09d", t.Nanosecond())
		s += "." + frac[:min(prec, 9)]
	}
	return s
}

func formatSeconds(ns int64, prec int) string {
	neg := ns < 0
	if neg {
		ns = -ns
	}
	s := strconv.FormatInt(ns/1e9, 10)
	if prec > 0 {
		frac := fmt.Sprintf("%09d", ns%1e9)
		s += "." + frac[:min(prec, 9)]
	}
	if neg {
		s = "-" + s
	}
	return s
}
