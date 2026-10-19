package pcapio

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readAll(t *testing.T, f *File) []Record {
	t.Helper()
	var out []Record
	for {
		r, err := f.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
}

func TestPcapngRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewNgWriter(&buf, SectionInfo{Comments: []string{"hello"}, OS: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.AddInterface(Interface{LinkType: LinkEthernet, SnapLen: 65535, Name: "en0", FCSLen: -1}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.AddInterface(Interface{LinkType: LinkRaw, SnapLen: 65535, Name: "utun3", FCSLen: -1}); err != nil {
		t.Fatal(err)
	}
	pkts := [][]byte{[]byte("abc"), []byte("defgh"), bytes.Repeat([]byte{7}, 1500)}
	for i, p := range pkts {
		rec := Record{TS: 1_700_000_000_123_456_789 + int64(i), Iface: uint32(i % 2), OrigLen: uint32(len(p) + 10), Flags: DirOutbound}
		if i == 1 {
			rec.Comments = []string{"marked by test"}
		}
		if err := w.WritePacket(rec, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.WriteSecrets(Secrets{Type: SecretsTLSKeyLog, Data: []byte("CLIENT_RANDOM aa bb\n")}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteNames([]NameRecord{{Addr: []byte{10, 0, 0, 1}, Names: []string{"router.lan"}}}); err != nil {
		t.Fatal(err)
	}
	w.Flush()

	f, err := Open(writeTemp(t, "x.pcapng", buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	recs := readAll(t, f)
	if f.Format != FormatPcapng || len(f.Interfaces) != 2 || f.Interfaces[1].Name != "utun3" || f.Interfaces[0].TSResol != 9 {
		t.Fatalf("bad header: %+v %+v", f.Format, f.Interfaces)
	}
	if len(f.Section.Comments) != 1 || f.Section.Comments[0] != "hello" || f.Section.Application != "lazysniffer" {
		t.Fatalf("bad section %+v", f.Section)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records", len(recs))
	}
	for i, r := range recs {
		if got := f.Data(r.DataOff, r.CapLen); !bytes.Equal(got, pkts[i]) {
			t.Fatalf("packet %d data mismatch", i)
		}
		if r.TS != 1_700_000_000_123_456_789+int64(i) || r.Iface != uint32(i%2) || r.Flags != DirOutbound {
			t.Fatalf("packet %d meta %+v", i, r)
		}
	}
	if len(recs[1].Comments) != 1 || recs[1].Comments[0] != "marked by test" {
		t.Fatalf("comments %+v", recs[1].Comments)
	}
	if len(f.Secrets) != 1 || f.Secrets[0].Type != SecretsTLSKeyLog {
		t.Fatalf("secrets %+v", f.Secrets)
	}
	if len(f.Names) != 1 || f.Names[0].Names[0] != "router.lan" {
		t.Fatalf("names %+v", f.Names)
	}
}

func TestPcapRoundTripAndGzip(t *testing.T) {
	for _, nanos := range []bool{false, true} {
		var buf bytes.Buffer
		w := NewPcapWriter(&buf, nanos)
		w.AddInterface(Interface{LinkType: LinkEthernet, SnapLen: 1000})
		w.WritePacket(Record{TS: 1_600_000_000_000_001_000}, []byte("hello"))
		w.WritePacket(Record{TS: 1_600_000_000_500_000_000, OrigLen: 100}, []byte("world!"))
		w.Flush()

		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		zw.Write(buf.Bytes())
		zw.Close()

		for _, data := range [][]byte{buf.Bytes(), gz.Bytes()} {
			f, err := Open(writeTemp(t, "x.pcap", data))
			if err != nil {
				t.Fatal(err)
			}
			recs := readAll(t, f)
			if len(recs) != 2 || string(f.Data(recs[1].DataOff, recs[1].CapLen)) != "world!" || recs[1].OrigLen != 100 {
				t.Fatalf("bad records %+v", recs)
			}
			if recs[0].TS != 1_600_000_000_000_001_000 || f.Interfaces[0].LinkType != LinkEthernet {
				t.Fatalf("ts %d", recs[0].TS)
			}
			f.Close()
		}
	}
}

func TestGrowingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "live.pcapng")
	out, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := NewNgWriter(out, SectionInfo{})
	w.AddInterface(Interface{LinkType: LinkEthernet, FCSLen: -1})
	w.WritePacket(Record{TS: 1}, []byte("one"))
	w.Flush()

	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if n := len(readAll(t, f)); n != 1 {
		t.Fatalf("got %d", n)
	}
	first, _ := f.Data(f.Pos()-36, 3), 0
	w.WritePacket(Record{TS: 2}, []byte("two"))
	w.Flush()
	if err := f.Refresh(); err != nil {
		t.Fatal(err)
	}
	recs := readAll(t, f)
	if len(recs) != 1 || string(f.Data(recs[0].DataOff, recs[0].CapLen)) != "two" {
		t.Fatalf("after refresh: %+v", recs)
	}
	_ = first
}

func TestConvertTS(t *testing.T) {
	cases := []struct {
		raw   uint64
		resol uint8
		want  int64
	}{
		{1_500_000, 6, 1_500_000_000},
		{15, 1, 1_500_000_000},
		{1_500_000_000_000, 12, 1_500_000_000},
		{3 << 20, 0x80 | 20, 3_000_000_000},
		{1<<19 | 1<<20, 0x80 | 20, 1_500_000_000},
	}
	for _, c := range cases {
		if got := ConvertTS(c.raw, c.resol); got != c.want {
			t.Errorf("ConvertTS(%d, %#x) = %d, want %d", c.raw, c.resol, got, c.want)
		}
	}
}

func FuzzOpen(f *testing.F) {
	var buf bytes.Buffer
	w, _ := NewNgWriter(&buf, SectionInfo{})
	w.AddInterface(Interface{LinkType: LinkEthernet, FCSLen: -1})
	w.WritePacket(Record{TS: 5, Comments: []string{"x"}}, []byte("data"))
	w.Flush()
	f.Add(buf.Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "f")
		os.WriteFile(p, data, 0o644)
		file, err := Open(p)
		if err != nil {
			return
		}
		defer file.Close()
		for i := 0; i < 10000; i++ {
			r, err := file.Next()
			if err != nil {
				return
			}
			file.Data(r.DataOff, r.CapLen)
		}
	})
}
