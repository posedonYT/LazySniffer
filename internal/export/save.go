package export

import (
	"fmt"
	"github.com/poseydon/lazysniffer/internal/keylog"
	"os"
	"path/filepath"
	"strings"

	"github.com/poseydon/lazysniffer/internal/pcapio"
	"github.com/poseydon/lazysniffer/internal/store"
)

// Format of a saved capture file.
type Format uint8

const (
	FormatPcapng Format = iota
	FormatPcap
	FormatPcapNs
)

// FormatFromPath picks a format by file extension (.pcap → pcap, else pcapng).
func FormatFromPath(path string) Format {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pcap", ".cap", ".dmp":
		return FormatPcap
	}
	return FormatPcapng
}

// SavePackets writes the given frames of a capture to path. Comments,
// interface descriptions and decryption secrets are kept in pcapng.
// EmbedKeys makes the next pcapng save include the loaded TLS secrets.
var EmbedKeys bool

func SavePackets(c *store.Capture, frames []uint32, path string, format Format) error {
	tmp := path + ".lazysniffer-tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	src := c.File()
	var w pcapio.Writer
	switch format {
	case FormatPcap, FormatPcapNs:
		pw := pcapio.NewPcapWriter(f, format == FormatPcapNs)
		w = pw
	default:
		ng, err := pcapio.NewNgWriter(f, pcapio.SectionInfo{
			Hardware: src.Section.Hardware, OS: src.Section.OS,
			Comments: src.Section.Comments,
		})
		if err != nil {
			return err
		}
		embed := EmbedKeys
		EmbedKeys = false
		for _, s := range src.Secrets {
			if embed && s.Type == pcapio.SecretsTLSKeyLog {
				continue // replaced by the merged key log below
			}
			if err := ng.WriteSecrets(s); err != nil {
				return err
			}
		}
		if embed {
			if data := keylog.Default.Export(); len(data) > 0 {
				if err := ng.WriteSecrets(pcapio.Secrets{Type: pcapio.SecretsTLSKeyLog, Data: data}); err != nil {
					return err
				}
			}
		}
		w = ng
	}
	// Map source interfaces to written interfaces lazily, so pcap (single
	// interface) works when all saved frames share one link type.
	ifaceMap := map[uint16]uint32{}
	for _, num := range frames {
		m := c.Frame(num)
		idx, seen := ifaceMap[m.Iface]
		if !seen {
			var iface pcapio.Interface
			if int(m.Iface) < len(src.Interfaces) {
				iface = src.Interfaces[m.Iface]
			}
			idx, err = w.AddInterface(iface)
			if err != nil {
				return fmt.Errorf("%w (packet %d uses %s)", err, num, iface.LinkType)
			}
			ifaceMap[m.Iface] = idx
		}
		rec := pcapio.Record{TS: m.TS, OrigLen: m.Len, Iface: idx, Flags: m.EPBFlags, Comments: c.Comments(num)}
		if err := w.WritePacket(rec, src.Data(m.Off, m.CapLen)); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return os.Rename(tmp, path)
}
