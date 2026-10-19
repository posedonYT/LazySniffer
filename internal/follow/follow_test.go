package follow

import (
	"context"
	"testing"

	"bytes"
	"crypto/tls"
	_ "github.com/poseydon/lazysniffer/internal/dissect/proto"
	"github.com/poseydon/lazysniffer/internal/keylog"
	"github.com/poseydon/lazysniffer/internal/store"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
	"os"
	"path/filepath"
	"time"
)

func TestFollowTCP(t *testing.T) {
	f := g.DefaultFlow()
	r := f.Rev()
	var pkts []g.Packet
	ts := int64(1e9)
	add := func(b []byte) { ts += 50e6; pkts = append(pkts, g.Packet{TS: ts, Data: b}) }
	add(g.TCP(f, 100, 0, g.SYN, 65535, nil, nil))
	add(g.TCP(r, 900, 101, g.SYN|g.ACK, 65535, nil, nil))
	add(g.TCP(f, 101, 901, g.ACK, 65535, nil, nil))
	add(g.TCP(f, 101, 901, g.ACK|g.PSH, 65535, nil, []byte("GET / HTTP/1.1\r\n")))
	add(g.TCP(f, 117, 901, g.ACK|g.PSH, 65535, nil, []byte("Host: x\r\n\r\n")))
	add(g.TCP(f, 101, 901, g.ACK|g.PSH, 65535, nil, []byte("GET / HTTP/1.1\r\n")))  // retransmission
	add(g.TCP(r, 916, 128, g.ACK|g.PSH, 65535, nil, []byte("XXworld")))             // out of order, overlaps 916-917
	add(g.TCP(r, 901, 128, g.ACK|g.PSH, 65535, nil, []byte("HTTP/1.1 200 OK\r\n"))) // 901..917 fills the gap
	add(g.TCP(r, 923, 128, g.FIN|g.ACK, 65535, nil, nil))
	c, err := store.Open(g.WritePcapng(t, pkts))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Load(context.Background(), nil)
	s, err := Build(context.Background(), c, TCP, 0)
	if err != nil {
		t.Fatal(err)
	}
	var client, server string
	for _, ch := range s.Chunks {
		if ch.FromServer {
			server += string(ch.Data)
		} else {
			client += string(ch.Data)
		}
	}
	if client != "GET / HTTP/1.1\r\nHost: x\r\n\r\n" {
		t.Errorf("client data %q", client)
	}
	if server != "HTTP/1.1 200 OK\r\nworld" {
		t.Errorf("server data %q", server)
	}
	if s.Client != "10.0.0.1:40000" || s.Server != "10.0.0.2:80" || s.ClientPkts != 5 || s.ServerPkts != 4 {
		t.Errorf("summary %+v", s)
	}
}

func TestFollowTLSDecrypted(t *testing.T) {
	cert := g.SelfSigned(t, "example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}
	cli := &tls.Config{ServerName: "example.test", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	writes, kl := g.TLSExchange(t, srv, cli, []byte("GET /secret HTTP/1.1\r\nHost: x\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
	path := filepath.Join(t.TempDir(), "k")
	os.WriteFile(path, kl, 0o600)
	keylog.Default.SetFiles(path)
	defer keylog.Default.SetFiles()
	f := g.DefaultFlow()
	f.B.Port = 443
	c, err := store.Open(g.WritePcapng(t, g.TLSCapture(f, writes, 1400)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Load(context.Background(), nil)
	s, err := Build(context.Background(), c, TLS, 0)
	if err != nil {
		t.Fatal(err)
	}
	var client, server string
	for _, ch := range s.Chunks {
		if ch.FromServer {
			server += string(ch.Data)
		} else {
			client += string(ch.Data)
		}
	}
	if client != "GET /secret HTTP/1.1\r\nHost: x\r\n\r\n" || server != "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" {
		t.Errorf("client %q server %q", client, server)
	}
	raw, _ := Build(context.Background(), c, TCP, 0)
	if raw.ClientBytes == 0 || bytes.Contains(rawBytes(raw), []byte("GET /secret")) {
		t.Errorf("raw TCP view should be encrypted: %d bytes", raw.ClientBytes)
	}
}

func rawBytes(s *Stream) []byte {
	var b []byte
	for _, c := range s.Chunks {
		b = append(b, c.Data...)
	}
	return b
}
