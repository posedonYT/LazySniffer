package export_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/export"
	"github.com/poseydon/lazysniffer/internal/store"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func TestWriteDissections(t *testing.T) {
	f := g.DefaultFlow()
	c := g.NewTCPConv(f, 1e9)
	c.Send(0, []byte("GET /a?x=\"1\"&y=<2> HTTP/1.1\r\nHost: h\r\n\r\n"))
	cp, err := store.Open(g.WritePcapng(t, c.Pkts))
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	cp.Load(context.Background(), nil)
	frames := engine.AllFrames(cp)
	for name, fm := range map[string]export.DissectFormat{"csv": export.DissectCSV, "text": export.DissectText, "details": export.DissectDetails,
		"json": export.DissectJSON, "psml": export.DissectPSML, "pdml": export.DissectPDML} {
		var b bytes.Buffer
		if err := export.WriteDissections(context.Background(), &b, cp, frames, fm); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out := b.String()
		if !strings.Contains(out, "GET /a") {
			t.Errorf("%s lacks the request:\n%s", name, out)
		}
		switch name {
		case "json":
			var v []map[string]any
			if err := json.Unmarshal(b.Bytes(), &v); err != nil || len(v) != len(frames) {
				t.Errorf("json: %v (%d)", err, len(v))
			}
			if !strings.Contains(out, `"http.request.method": "GET"`) {
				t.Errorf("json lacks method field")
			}
		case "psml", "pdml":
			if err := xml.NewDecoder(strings.NewReader(out)).Decode(new(any)); err != nil && !strings.Contains(err.Error(), "unexpected") {
				t.Errorf("%s: %v", name, err)
			}
			d := xml.NewDecoder(strings.NewReader(out))
			for {
				if _, err := d.Token(); err != nil {
					if err.Error() != "EOF" {
						t.Errorf("%s not well-formed: %v", name, err)
					}
					break
				}
			}
		}
	}
}
