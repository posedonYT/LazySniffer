// Package export renders dissections as text, CSV, JSON and other formats.
package export

import (
	"fmt"
	"io"
	"strings"

	"github.com/poseydon/lazysniffer/internal/dissect"
)

// WriteTree prints a protocol tree like `tshark -V`. Hidden items are skipped.
func WriteTree(w io.Writer, root *dissect.Node) error {
	var err error
	root.Walk(func(n *dissect.Node, depth int) bool {
		if n.Flags&dissect.NodeHidden != 0 {
			return false
		}
		if err == nil {
			_, err = fmt.Fprintf(w, "%s%s\n", strings.Repeat("    ", depth), n.Text())
		}
		return true
	})
	return err
}

// WriteHex prints bytes as a hex dump with an ASCII column.
func WriteHex(w io.Writer, b []byte) error {
	for off := 0; off < len(b); off += 16 {
		end := min(off+16, len(b))
		var hex, asc strings.Builder
		for i := off; i < off+16; i++ {
			if i == off+8 {
				hex.WriteByte(' ')
			}
			if i < end {
				fmt.Fprintf(&hex, "%02x ", b[i])
				c := b[i]
				if c < 0x20 || c > 0x7e {
					c = '.'
				}
				asc.WriteByte(c)
			} else {
				hex.WriteString("   ")
			}
		}
		if _, err := fmt.Fprintf(w, "%04x  %s %s\n", off, hex.String(), asc.String()); err != nil {
			return err
		}
	}
	return nil
}
