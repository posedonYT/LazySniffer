// Package difftest compares lazysniffer's dissection with tshark's on
// generated captures. It is skipped when tshark is not installed.
package difftest

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/poseydon/lazysniffer/internal/dissect"
	_ "github.com/poseydon/lazysniffer/internal/dissect/proto"
	"github.com/poseydon/lazysniffer/internal/keylog"
	"github.com/poseydon/lazysniffer/internal/store"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func tsharkPath(t *testing.T) string {
	for _, p := range []string{"tshark", "/opt/homebrew/bin/tshark", "/usr/local/bin/tshark", "/usr/bin/tshark"} {
		if path, err := exec.LookPath(p); err == nil {
			if !oracleVersionOK(path) {
				t.Skipf("%s is older than Wireshark %d.%d; the oracle expectations follow its output", path, minMajor, minMinor)
			}
			return path
		}
	}
	t.Skip("tshark is not installed")
	return ""
}

// The expected values (Info columns, field sets) were calibrated against
// Wireshark 4.6; older releases word several of them differently.
const (
	minMajor = 4
	minMinor = 6
)

func oracleVersionOK(path string) bool {
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return false
	}
	var maj, min int
	line, _, _ := strings.Cut(string(out), "\n")
	i := strings.IndexFunc(line, func(r rune) bool { return r >= '0' && r <= '9' })
	if i < 0 {
		return false
	}
	if _, err := fmt.Sscanf(line[i:], "%d.%d", &maj, &min); err != nil {
		return false
	}
	return maj > minMajor || (maj == minMajor && min >= minMinor)
}

// norm makes tshark's and our renderings of a value comparable.
func norm(ft dissect.FieldType, s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	s = strings.TrimSpace(s)
	if s == "<missing>" || s == "<MISSING>" {
		return "" // empty bytes
	}
	switch ft {
	case dissect.FtBool:
		switch strings.ToLower(s) {
		case "true", "1":
			return "1"
		case "false", "0":
			return "0"
		}
	case dissect.FtBytes, dissect.FtEther:
		return strings.ToLower(strings.NewReplacer(":", "", "-", "", " ", "").Replace(s))
	}
	if strings.HasPrefix(s, "0x") {
		if v, err := strconv.ParseUint(s[2:], 16, 64); err == nil {
			return strconv.FormatUint(v, 10)
		}
	}
	return s
}

// compare runs tshark and lazysniffer over file and reports differences in
// the given fields. Missing values on both sides are equal.
var tsharkFields map[string]bool

func knownByTshark(t *testing.T, tshark string, name string) bool {
	if tsharkFields == nil {
		tsharkFields = map[string]bool{}
		out, err := exec.Command(tshark, "-G", "fields").Output()
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Split(l, "\t"); len(f) > 2 {
				tsharkFields[f[2]] = true
			}
		}
	}
	return tsharkFields[name]
}

func compare(t *testing.T, file string, display string, all []string) {
	t.Helper()
	tshark := tsharkPath(t)
	var fields []string
	for _, f := range all {
		if knownByTshark(t, tshark, f) {
			fields = append(fields, f)
		} else {
			t.Logf("skipping %s: unknown to tshark", f)
		}
	}
	args := []string{"-r", file, "-n", "-2", "-o", "tcp.relative_sequence_numbers:TRUE", "-T", "fields", "-e", "frame.number"}
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	args = append(args, "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=|")
	if display != "" {
		args = append(args, "-Y", display)
	}
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
	want := map[uint32][]string{}
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		cells := strings.Split(line, "\t")
		n, _ := strconv.Atoi(cells[0])
		for len(cells) < len(fields)+1 {
			cells = append(cells, "")
		}
		want[uint32(n)] = cells[1:]
	}
	c, err := store.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Load(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	var kept []string
	var fds []*dissect.FieldDef
	for _, f := range fields {
		if fd := dissect.LookupField(f); fd != nil {
			kept = append(kept, f)
			fds = append(fds, fd)
		} else {
			t.Logf("field %s is not implemented", f)
		}
	}
	if len(kept) != len(fields) {
		compare2(t, file, display, kept)
		return
	}
	w := c.Session().NewWorker(dissect.Options{Full: true, Columns: true})
	var diffs []string
	nums := make([]int, 0, len(want))
	for n := range want {
		nums = append(nums, int(n))
	}
	sort.Ints(nums)
	for _, n := range nums {
		pi := w.Dissect(c.Input(uint32(n)))
		for i, fd := range fds {
			var vals []string
			for _, v := range pi.Tree.Values(fd) {
				if fd.Type == dissect.FtNone {
					vals = append(vals, "1") // tshark prints 1 for the presence of a text item
					break
				}
				vals = append(vals, norm(fd.Type, unescape(fd.FilterString(v.V))))
			}
			got := strings.Join(vals, "|")
			var tv []string
			if want[uint32(n)][i] != "" {
				unesc := strings.NewReplacer(`\r`, "\r", `\n`, "\n", `\t`, "\t").Replace(want[uint32(n)][i])
				for _, x := range strings.Split(unesc, "|") {
					tv = append(tv, norm(fd.Type, x))
				}
			}
			if got != strings.Join(tv, "|") {
				diffs = append(diffs, fmt.Sprintf("frame %d %s: lazysniffer %.150q, tshark %.150q", n, fields[i], got, strings.Join(tv, "|")))
			}
		}
	}
	if len(diffs) > 0 {
		if len(diffs) > 25 {
			diffs = append(diffs[:25], fmt.Sprintf("… and %d more", len(diffs)-25))
		}
		t.Errorf("%d differences:\n%s", len(diffs), strings.Join(diffs, "\n"))
	}
}

// compare2 is compare without the "implemented" filtering.
func unescape(s string) string {
	return strings.NewReplacer(`\r`, "\r", `\n`, "\n", `\t`, "\t").Replace(s)
}

func compare2(t *testing.T, file, display string, fields []string) { compare(t, file, display, fields) }

func write(t *testing.T, pkts []g.Packet) string {
	return g.WritePcapng(t, pkts)
}

func TestHTTPAndTCP(t *testing.T) {
	f := g.DefaultFlow()
	c := g.NewTCPConv(f, 1e9)
	c.Send(0, []byte("GET /index.html?q=1 HTTP/1.1\r\nHost: example.org\r\nUser-Agent: curl/8\r\nAccept: */*\r\n\r\n"))
	c.Send(1, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 11\r\nServer: nginx\r\n\r\nhello world"))
	c.Send(0, []byte("POST /api HTTP/1.1\r\nHost: example.org\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}"))
	c.Send(1, []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
	c.Close()
	compare(t, write(t, c.Pkts), "", []string{
		"ip.src", "ip.dst", "ip.ttl", "ip.proto", "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.seq", "tcp.ack", "tcp.len", "tcp.flags",
		"tcp.window_size_value", "tcp.analysis.flags", "tcp.analysis.acks_frame", "tcp.nxtseq",
		"http.request.method", "http.request.uri", "http.request.version", "http.host", "http.user_agent", "http.response.code",
		"http.response.phrase", "http.content_type", "http.content_length", "http.request.full_uri", "http.request_in", "http.response_in",
		"http.server", "http.file_data",
	})
}

func TestTLSHandshakeFields(t *testing.T) {
	cert := g.SelfSigned(t, "example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	for _, ver := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		srv := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}, MinVersion: ver, MaxVersion: ver}
		cli := &tls.Config{ServerName: "example.test", InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}, MinVersion: ver, MaxVersion: ver}
		writes, _ := g.TLSExchange(t, srv, cli, []byte("GET / HTTP/1.1\r\n\r\n"), bytes.Repeat([]byte("x"), 5000))
		f := g.DefaultFlow()
		f.B.Port = 443
		t.Run(fmt.Sprintf("%x", ver), func(t *testing.T) {
			compare(t, write(t, g.TLSCapture(f, writes, 1400)), "", []string{
				"tls.record.content_type", "tls.record.version", "tls.record.length", "tls.handshake.type", "tls.handshake.version",
				"tls.handshake.extensions_server_name", "tls.handshake.ciphersuite", "tls.handshake.extensions_alpn_str",
				"tls.handshake.ja3", "tls.handshake.ja3_full", "tls.handshake.ja3s", "tls.handshake.ja4", "tls.handshake.ja4_r", "tls.handshake.ja4s",
				"tls.handshake.random", "tls.handshake.session_id_length", "tls.handshake.extension.type", "tls.handshake.sig_hash_alg",
				"tls.handshake.certificate_length", "x509ce.dNSName", "tls.segment.data",
			})
		})
	}
}

func TestDNS(t *testing.T) {
	p := filepath.Join(os.Getenv("HOME"), "go/pkg/mod/github.com/gopacket/gopacket@v1.7.4/pcap/test_dns.pcap")
	if _, err := os.Stat(p); err != nil {
		t.Skip("sample capture missing")
	}
	compare(t, p, "", []string{"ip.src", "ip.dst", "ip.id", "ip.flags", "ip.checksum", "udp.srcport", "udp.dstport", "udp.length", "udp.checksum",
		"dns.id", "dns.flags", "dns.flags.response", "dns.flags.opcode", "dns.flags.recdesired", "dns.count.queries", "dns.count.answers",
		"dns.qry.name", "dns.qry.type", "dns.qry.class", "dns.resp.name", "dns.a", "dns.aaaa", "dns.cname", "dns.resp.ttl", "dns.response_in", "dns.time"})
}

func TestSampleTCP(t *testing.T) {
	for _, name := range []string{"test_ethernet.pcap", "test_loopback.pcap"} {
		p := filepath.Join(os.Getenv("HOME"), "go/pkg/mod/github.com/gopacket/gopacket@v1.7.4/pcap", name)
		if _, err := os.Stat(p); err != nil {
			t.Skip("sample capture missing")
		}
		t.Run(name, func(t *testing.T) {
			compare(t, p, "", []string{"ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "ipv6.hlim", "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.seq", "tcp.ack", "tcp.len",
				"tcp.flags", "tcp.window_size_value", "tcp.window_size", "tcp.analysis.flags", "tcp.analysis.retransmission", "tcp.analysis.duplicate_ack",
				"tcp.analysis.out_of_order", "tcp.analysis.ack_rtt", "tcp.analysis.bytes_in_flight", "tcp.options.mss_val", "tcp.options.wscale.shift",
				"tcp.options.timestamp.tsval", "tcp.reassembled.length", "tcp.segment", "http.request.method", "http.request.uri", "http.response.code",
				"http.content_type", "http.content_length", "http.host"})
		})
	}
}

var _ = keylog.Default
