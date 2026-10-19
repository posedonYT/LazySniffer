package proto

import (
	"testing"

	d "github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/pcapio"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

var fuzzPorts = []uint16{21, 22, 23, 25, 53, 67, 80, 110, 123, 143, 161, 443, 500, 514, 1080, 1194, 1701, 1883, 3306, 3478, 4500, 5432, 6379, 8083, 51820}

// FuzzApps feeds arbitrary payloads to every application dissector over TCP
// (as a three-segment stream) and UDP.
func FuzzApps(f *testing.F) {
	f.Add(uint8(0), false, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	f.Add(uint8(0), true, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00"))
	f.Add(uint8(0), true, []byte{0x16, 3, 1, 0, 5, 1, 0, 0, 1, 0})
	f.Add(uint8(0), true, []byte("*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n"))
	f.Add(uint8(0), true, []byte{0x10, 0x0c, 0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 60, 0, 0})
	f.Add(uint8(0), true, []byte("SSH-2.0-x\r\n\x00\x00\x00\x0c\x0a\x14abcdefghijkl"))
	f.Add(uint8(0), false, []byte{0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x40, 0x20, 0, 0, 0, 0})
	f.Add(uint8(0), false, []byte{1, 0, 0, 0, 0, 0, 0, 0})
	f.Add(uint8(0), false, []byte{0x30, 0x29, 2, 1, 0, 4, 6, 'p', 'u', 'b', 'l', 'i', 'c', 0xa0, 0x1c})
	d.StrictBugs = true
	f.Fuzz(func(t *testing.T, sel uint8, tcp bool, data []byte) {
		port := fuzzPorts[int(sel)%len(fuzzPorts)]
		fl := g.DefaultFlow()
		fl.B.Port = port
		var frames [][]byte
		if tcp {
			c := g.NewTCPConv(fl, 1e9)
			c.Send(0, data)
			c.Send(1, data)
			c.Send(0, data)
			for _, p := range c.Pkts {
				frames = append(frames, p.Data)
			}
		} else {
			frames = [][]byte{g.UDP(fl, data), g.UDP(fl.Rev(), data), g.UDP(fl, data)}
		}
		sess := d.NewSession([]pcapio.Interface{{LinkType: pcapio.LinkEthernet}})
		w1 := sess.NewWorker(d.Options{Want: make([]bool, d.NumFields())})
		full := sess.NewWorker(d.Options{Full: true, Columns: true})
		for i, fr := range frames {
			fi := &d.FrameInput{Num: uint32(i + 1), TS: int64(i+1) * 1e6, CapLen: uint32(len(fr)), Len: uint32(len(fr)), Data: fr}
			w1.FirstPass(fi)
		}
		for i, fr := range frames {
			fi := &d.FrameInput{Num: uint32(i + 1), TS: int64(i+1) * 1e6, CapLen: uint32(len(fr)), Len: uint32(len(fr)), Data: fr}
			pi := full.Dissect(fi)
			pi.Tree.Root.Walk(func(n *d.Node, _ int) bool { _ = n.Text(); return true })
		}
	})
}
