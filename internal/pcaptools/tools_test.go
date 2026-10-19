package pcaptools

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/poseydon/lazysniffer/internal/pcapio"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func sample(t *testing.T, n int, offset int64) string {
	var pk []g.Packet
	f := g.DefaultFlow()
	for i := 0; i < n; i++ {
		pk = append(pk, g.Packet{TS: offset + int64(i)*1e9, Data: g.UDP(f, []byte{byte(i), 1, 2, 3})})
	}
	return g.WritePcapng(t, pk)
}

func TestToolsRoundTrip(t *testing.T) {
	a := sample(t, 5, 100e9)
	b := sample(t, 5, 102500e6) // interleaves with a
	pk, _, err := Merge([]string{a, b}, false)
	if err != nil || len(pk) != 10 {
		t.Fatalf("merge %d %v", len(pk), err)
	}
	for i := 1; i < len(pk); i++ {
		if pk[i].Rec.TS < pk[i-1].Rec.TS {
			t.Fatal("merge is not chronological")
		}
	}
	out := filepath.Join(t.TempDir(), "m.pcapng")
	f, _ := os.Create(out)
	if err := Write(f, pk, WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	in, err := Summarize(out)
	if err != nil || in.Packets != 10 || in.Duration() < 6 {
		t.Fatalf("%+v %v", in, err)
	}
	ed := Edit(pk, EditOptions{Keep: []Range{{1, 3}, {8, 0}}, SnapLen: 40, TimeShift: 5e9})
	if len(ed) != 6 || len(ed[0].Data) != 40 || ed[0].Rec.TS != pk[0].Rec.TS+5e9 {
		t.Errorf("edit %d %d", len(ed), len(ed[0].Data))
	}
	dd := Edit(append(append([]Packet(nil), pk[:3]...), pk[0], pk[1]), EditOptions{Dedup: 5})
	if len(dd) != 3 {
		t.Errorf("dedup kept %d", len(dd))
	}
	parts := Split(pk, 4, 0)
	if len(parts) != 3 || len(parts[2]) != 2 {
		t.Errorf("split %d", len(parts))
	}
	if rs, err := ParseRanges("1-3,7,9-"); err != nil || len(rs) != 3 || rs[2].To != 0 {
		t.Errorf("ranges %v %v", rs, err)
	}
	// text2pcap
	txt := "0000 02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 00 ................\n0010 00 1c 00 01\n\n0000 aa bb cc\n"
	tp, err := Text2Pcap(strings.NewReader(txt), pcapio.LinkEthernet, time.Unix(1000, 0))
	if err != nil || len(tp) != 2 || len(tp[0].Data) != 20 || len(tp[1].Data) != 3 {
		t.Errorf("text2pcap %v %v", tp, err)
	}
}

// TestAgainstWireshark checks our files with capinfos/editcap/mergecap.
func TestAgainstWireshark(t *testing.T) {
	capinfos, err := exec.LookPath("capinfos")
	if err != nil {
		for _, p := range []string{"/opt/homebrew/bin/capinfos", "/usr/local/bin/capinfos"} {
			if _, e := os.Stat(p); e == nil {
				capinfos, err = p, nil
				break
			}
		}
	}
	if err != nil {
		t.Skip("capinfos is not installed")
	}
	a, b := sample(t, 5, 100e9), sample(t, 5, 102500e6)
	pk, _, _ := Merge([]string{a, b}, false)
	for name, format := range map[string]pcapio.Format{"x.pcapng": pcapio.FormatPcapng, "x.pcap": pcapio.FormatPcap} {
		path := filepath.Join(t.TempDir(), name)
		f, _ := os.Create(path)
		if err := Write(f, pk, WriteOptions{Format: format}); err != nil {
			t.Fatal(err)
		}
		f.Close()
		out, err := exec.Command(capinfos, "-c", "-u", path).CombinedOutput()
		if err != nil || !bytes.Contains(out, []byte("Number of packets:   10")) {
			t.Errorf("%s: capinfos: %v\n%s", name, err, out)
		}
	}
	// our merged output must equal mergecap's packet order
	mergecap := filepath.Join(filepath.Dir(capinfos), "mergecap")
	if _, err := os.Stat(mergecap); err == nil {
		ref := filepath.Join(t.TempDir(), "ref.pcapng")
		if out, err := exec.Command(mergecap, "-w", ref, a, b).CombinedOutput(); err != nil {
			t.Fatalf("mergecap: %v\n%s", err, out)
		}
		rp, _, _ := Read(ref)
		if len(rp) != len(pk) {
			t.Fatalf("mergecap %d packets, ours %d", len(rp), len(pk))
		}
		for i := range rp {
			if rp[i].Rec.TS != pk[i].Rec.TS || !bytes.Equal(rp[i].Data, pk[i].Data) {
				t.Fatalf("packet %d differs from mergecap", i+1)
			}
		}
	}
}
