package export

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/store"
)

// DissectFormat is a packet dissection export format.
type DissectFormat int

const (
	DissectText    DissectFormat = iota // summary lines (tshark default)
	DissectDetails                      // full protocol trees (tshark -V)
	DissectCSV
	DissectJSON
	DissectPSML
	DissectPDML
)

// DissectFormatFromPath picks a format from the file extension.
func DissectFormatFromPath(p string) DissectFormat {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".csv":
		return DissectCSV
	case ".json":
		return DissectJSON
	case ".psml":
		return DissectPSML
	case ".pdml", ".xml":
		return DissectPDML
	case ".log", ".details":
		return DissectDetails
	}
	return DissectText
}

// summary is one packet-list row.
type summary struct {
	No       uint32
	Time     float64
	Src, Dst string
	Protocol string
	Length   uint32
	Info     string
}

func rowOf(pi *dissect.PacketInfo) summary {
	src, dst := pi.Src, pi.Dst
	if src.IsZero() {
		src, dst = pi.NetSrc, pi.NetDst
	}
	if src.IsZero() {
		src, dst = pi.DLSrc, pi.DLDst
	}
	return summary{No: pi.Num, Time: float64(pi.RelTS) / 1e9, Src: src.String(), Dst: dst.String(), Protocol: pi.Protocol(), Length: pi.Len, Info: pi.Info()}
}

// WriteDissections writes the given frames in the requested format.
func WriteDissections(ctx context.Context, w io.Writer, c *store.Capture, frames []uint32, format DissectFormat) error {
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	full := format == DissectDetails || format == DissectJSON || format == DissectPDML
	wk := c.Session().NewWorker(dissect.Options{Full: full, Columns: true, Want: make([]bool, dissect.NumFields())})
	var cw *csv.Writer
	switch format {
	case DissectCSV:
		cw = csv.NewWriter(bw)
		cw.Write([]string{"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"})
	case DissectJSON:
		bw.WriteString("[\n")
	case DissectPSML:
		bw.WriteString("<?xml version=\"1.0\"?>\n<psml version=\"0\">\n<structure><section>No.</section><section>Time</section><section>Source</section><section>Destination</section><section>Protocol</section><section>Length</section><section>Info</section></structure>\n")
	case DissectPDML:
		bw.WriteString("<?xml version=\"1.0\"?>\n<pdml version=\"0\" creator=\"lazysniffer\">\n")
	}
	for i, num := range frames {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fi := c.Input(num)
		if fi == nil {
			continue
		}
		pi := wk.Dissect(fi)
		s := rowOf(pi)
		switch format {
		case DissectText:
			fmt.Fprintf(bw, "%6d %12.6f %s → %s %s %d %s\n", s.No, s.Time, s.Src, s.Dst, s.Protocol, s.Length, s.Info)
		case DissectDetails:
			fmt.Fprintf(bw, "%6d %12.6f %s → %s %s %d %s\n", s.No, s.Time, s.Src, s.Dst, s.Protocol, s.Length, s.Info)
			if err := WriteTree(bw, &pi.Tree.Root); err != nil {
				return err
			}
			bw.WriteString("\n")
		case DissectCSV:
			cw.Write([]string{fmt.Sprint(s.No), fmt.Sprintf("%.9f", s.Time), s.Src, s.Dst, s.Protocol, fmt.Sprint(s.Length), s.Info})
		case DissectJSON:
			obj := map[string]any{"_index": "packets", "_type": "doc", "_score": nil, "_source": map[string]any{"layers": layersOf(pi)}}
			b, err := json.MarshalIndent(obj, "  ", "  ")
			if err != nil {
				return err
			}
			if i > 0 {
				bw.WriteString(",\n")
			}
			bw.WriteString("  ")
			bw.Write(b)
		case DissectPSML:
			bw.WriteString("<packet>")
			for _, cell := range []string{fmt.Sprint(s.No), fmt.Sprintf("%.6f", s.Time), s.Src, s.Dst, s.Protocol, fmt.Sprint(s.Length), s.Info} {
				bw.WriteString("<section>")
				xml.EscapeText(bw, []byte(cell))
				bw.WriteString("</section>")
			}
			bw.WriteString("</packet>\n")
		case DissectPDML:
			writePDML(bw, pi)
		}
	}
	switch format {
	case DissectCSV:
		cw.Flush()
		return cw.Error()
	case DissectJSON:
		bw.WriteString("\n]\n")
	case DissectPSML:
		bw.WriteString("</psml>\n")
	case DissectPDML:
		bw.WriteString("</pdml>\n")
	}
	return nil
}

// layersOf groups the fields of a frame by protocol, like tshark -T json.
func layersOf(pi *dissect.PacketInfo) map[string]any {
	layers := map[string]any{}
	for _, top := range pi.Tree.Root.Children() {
		if top.Field == nil {
			continue
		}
		fields := map[string][]string{}
		top.Walk(func(n *dissect.Node, _ int) bool {
			if n.Field != nil && n != top && n.Field.Type != dissect.FtNone {
				fields[n.Field.Abbrev] = append(fields[n.Field.Abbrev], n.Field.Display(n.Value))
			}
			return true
		})
		obj := map[string]any{}
		for k, v := range fields {
			if len(v) == 1 {
				obj[k] = v[0]
			} else {
				obj[k] = v
			}
		}
		layers[top.Field.Abbrev] = obj
	}
	return layers
}

func writePDML(w *bufio.Writer, pi *dissect.PacketInfo) {
	w.WriteString("<packet>\n")
	for _, top := range pi.Tree.Root.Children() {
		fmt.Fprintf(w, "  <proto name=\"%s\" showname=\"%s\" pos=\"%d\" size=\"%d\">\n", xmlAttr(abbrevOf(top)), xmlAttr(top.Text()), top.Start, top.Length)
		top.Walk(func(n *dissect.Node, depth int) bool {
			if n == top {
				return true
			}
			fmt.Fprintf(w, "%s<field name=\"%s\" showname=\"%s\" pos=\"%d\" size=\"%d\"", strings.Repeat("  ", depth+1), xmlAttr(abbrevOf(n)), xmlAttr(n.Text()), n.Start, n.Length)
			if n.Field != nil && n.Field.Type != dissect.FtNone {
				fmt.Fprintf(w, " show=\"%s\"", xmlAttr(n.Field.Display(n.Value)))
			}
			w.WriteString("/>\n")
			return true
		})
		w.WriteString("  </proto>\n")
	}
	w.WriteString("</packet>\n")
}

func abbrevOf(n *dissect.Node) string {
	if n.Field != nil {
		return n.Field.Abbrev
	}
	return ""
}

func xmlAttr(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}
