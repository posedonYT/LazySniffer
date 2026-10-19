package difftest

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/poseydon/lazysniffer/internal/keylog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/pcapio"
	"github.com/poseydon/lazysniffer/internal/store"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

// compareColumns compares the Protocol and Info columns with tshark's.
func compareColumns(t *testing.T, file string) {
	t.Helper()
	tshark := tsharkPath(t)
	args := []string{"-r", file, "-n", "-2", "-T", "fields", "-e", "frame.number", "-e", "_ws.col.protocol", "-e", "_ws.col.info", "-E", "separator=\t"}
	if kf := os.Getenv("DIFFTEST_KEYLOG"); kf != "" {
		args = append(args, "-o", "tls.keylog_file:"+kf)
	}
	cmd := exec.Command(tshark, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("tshark: %v\n%s", err, stderr.String())
	}
	c, err := store.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Load(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	w := c.Session().NewWorker(dissect.Options{Full: false, Columns: true, Want: make([]bool, dissect.NumFields())})
	var diffs []string
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		cells := strings.SplitN(line, "\t", 3)
		for len(cells) < 3 {
			cells = append(cells, "")
		}
		n, _ := strconv.Atoi(cells[0])
		pi := w.Dissect(c.Input(uint32(n)))
		wantProto, wantInfo := cells[1], strings.TrimSpace(unescape(cells[2]))
		if strings.HasSuffix(wantProto, "/IMF") {
			continue // the Internet Message Format dissector is not implemented
		}
		gotInfo := strings.TrimSpace(pi.Info())
		if pi.Protocol() != wantProto || gotInfo != wantInfo {
			diffs = append(diffs, fmt.Sprintf("frame %d:\n   ours   %s | %.140s\n   tshark %s | %.140s", n, pi.Protocol(), gotInfo, wantProto, wantInfo))
		}
	}
	if len(diffs) > 0 {
		if len(diffs) > 12 {
			diffs = append(diffs[:12], fmt.Sprintf("… %d more", len(diffs)-12))
		}
		t.Errorf("%d column differences:\n%s", len(diffs), strings.Join(diffs, "\n"))
	}
}

func TestColumns(t *testing.T) {
	files := map[string]string{}
	files["services"] = g.WritePcapng(t, g.SampleServices())
	files["text"] = g.WritePcapng(t, g.SampleTextProtocols())
	files["databases"] = g.WritePcapng(t, g.SampleDatabases())
	files["http2"] = g.WritePcapng(t, g.SampleHTTP2(8083))
	files["voip"] = g.WritePcapng(t, g.SampleVoIP())
	_ = pcapio.LinkEthernet
	for name, f := range files {
		t.Run(name, func(t *testing.T) { compareColumns(t, f) })
	}
	home := os.Getenv("HOME")
	for _, name := range []string{"test_ethernet.pcap", "test_loopback.pcap", "test_dns.pcap"} {
		p := filepath.Join(home, "go/pkg/mod/github.com/gopacket/gopacket@v1.7.4/pcap", name)
		if _, err := os.Stat(p); err == nil {
			t.Run(name, func(t *testing.T) { compareColumns(t, p) })
		}
	}
	// TLS 1.2 and 1.3, plain and decrypted
	cert := g.SelfSigned(t, "example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	for name, ver := range map[string]uint16{"tls12": tls.VersionTLS12, "tls13": tls.VersionTLS13} {
		srv := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}, MinVersion: ver, MaxVersion: ver}
		cli := &tls.Config{ServerName: "example.test", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}, MinVersion: ver, MaxVersion: ver}
		writes, kl := g.TLSExchange(t, srv, cli, []byte("GET /a HTTP/1.1\r\nHost: example.test\r\n\r\n"),
			append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 30000\r\n\r\n"), make([]byte, 30000)...))
		fl := g.DefaultFlow()
		fl.B.Port = 443
		file := g.WritePcapng(t, g.TLSCapture(fl, writes, 1400))
		t.Run(name, func(t *testing.T) { compareColumns(t, file) })
		kfile := filepath.Join(t.TempDir(), "keys.log")
		os.WriteFile(kfile, kl, 0o600)
		keylog.Default.SetFiles(kfile)
		t.Run(name+"-decrypted", func(t *testing.T) {
			t.Setenv("DIFFTEST_KEYLOG", kfile)
			compareColumns(t, file)
		})
		keylog.Default.SetFiles()
	}
}
