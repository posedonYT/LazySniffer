package proto

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	d "github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/pcapio"
	"github.com/poseydon/lazysniffer/internal/store"
)

func samplePackets(f *testing.F) {
	gp := filepath.Join(os.Getenv("HOME"), "go/pkg/mod/github.com/gopacket/gopacket@v1.7.4/pcap")
	for _, name := range []string{"test_ethernet.pcap", "test_dns.pcap"} {
		c, err := store.Open(filepath.Join(gp, name))
		if err != nil {
			continue
		}
		c.Load(context.Background(), nil)
		for i := 1; i <= c.Count() && i <= 20; i++ {
			fi := c.Input(uint32(i))
			f.Add(uint16(pcapio.LinkEthernet), append([]byte(nil), fi.Data...))
		}
		c.Close()
	}
}

func FuzzDissect(f *testing.F) {
	samplePackets(f)
	f.Add(uint16(pcapio.LinkRaw), []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Add(uint16(pcapio.LinkPKTAP), make([]byte, 160))
	d.StrictBugs = true
	f.Fuzz(func(t *testing.T, link uint16, data []byte) {
		lt := pcapio.LinkType(link % 300)
		sess := d.NewSession([]pcapio.Interface{{LinkType: lt}})
		w1 := sess.NewWorker(d.Options{Want: make([]bool, d.NumFields())})
		full := sess.NewWorker(d.Options{Full: true, Columns: true})
		for i := uint32(1); i <= 3; i++ {
			fi := &d.FrameInput{Num: i, TS: int64(i), CapLen: uint32(len(data)), Len: uint32(len(data)), Data: data}
			w1.FirstPass(fi)
			pi := full.Dissect(fi)
			pi.Tree.Root.Walk(func(n *d.Node, _ int) bool { _ = n.Text(); return true })
		}
	})
}
