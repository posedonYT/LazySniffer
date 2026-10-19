package pktgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// Write records the bytes written by each side of a connection, in order.
type Write struct {
	Server bool
	Data   []byte
}

type recConn struct {
	net.Conn
	server bool
	mu     *sync.Mutex
	log    *[]Write
}

func (r *recConn) Write(b []byte) (int, error) {
	r.mu.Lock()
	*r.log = append(*r.log, Write{Server: r.server, Data: append([]byte(nil), b...)})
	r.mu.Unlock()
	return r.Conn.Write(b)
}

// SelfSigned returns a certificate for host valid from notBefore to notAfter.
func SelfSigned(t testing.TB, host string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: host, Organization: []string{"lazysniffer test"}},
		NotBefore:    notBefore, NotAfter: notAfter,
		DNSNames:    []string{host, "www." + host},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TLSExchange runs a real TLS handshake plus one request/response over an
// in-memory pipe and returns what each side wrote (and the key log).
func TLSExchange(t testing.TB, server, client *tls.Config, request, response []byte) ([]Write, []byte) {
	t.Helper()
	a, b := net.Pipe()
	var mu sync.Mutex
	var log []Write
	var keylog safeBuf
	client.KeyLogWriter = &keylog
	cc := tls.Client(&recConn{Conn: a, mu: &mu, log: &log}, client)
	sc := tls.Server(&recConn{Conn: b, server: true, mu: &mu, log: &log}, server)
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, len(request))
		if _, err := io.ReadFull(sc, buf); err != nil {
			done <- err
			return
		}
		_, err := sc.Write(response)
		// Read the client's close_notify, then answer it.
		io.Copy(io.Discard, sc)
		sc.Close()
		done <- err
	}()
	if _, err := cc.Write(request); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(response))
	if _, err := io.ReadFull(cc, buf); err != nil {
		t.Fatal(err)
	}
	cc.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	a.Close()
	b.Close()
	mu.Lock()
	defer mu.Unlock()
	return log, keylog.Bytes()
}

type safeBuf struct {
	mu sync.Mutex
	b  []byte
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.b = append(s.b, p...)
	s.mu.Unlock()
	return len(p), nil
}

func (s *safeBuf) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b...)
}

// TLSCapture turns recorded writes into a TCP connection's packets.
func TLSCapture(f Flow, writes []Write, mss int) []Packet {
	c := NewTCPConv(f, 1_700_000_000_000_000_000)
	c.MSS = mss
	for _, w := range writes {
		dir := 0
		if w.Server {
			dir = 1
		}
		c.Send(dir, w.Data)
	}
	c.Close()
	return c.Pkts
}
