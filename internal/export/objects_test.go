package export_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/poseydon/lazysniffer/internal/dissect/proto"
	"github.com/poseydon/lazysniffer/internal/export"
	"github.com/poseydon/lazysniffer/internal/keylog"
	"github.com/poseydon/lazysniffer/internal/store"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func TestObjectsAndCredentials(t *testing.T) {
	cert := g.SelfSigned(t, "example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}
	cli := &tls.Config{ServerName: "example.test", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	img := bytes.Repeat([]byte{0xff, 0xd8, 0xff, 0xe0}, 5000)
	resp := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n", len(img))), img...)
	writes, kl := g.TLSExchange(t, srv, cli, []byte("GET /img/cat.jpg HTTP/1.1\r\nHost: media.example\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n"), resp)
	path := filepath.Join(t.TempDir(), "keys")
	os.WriteFile(path, kl, 0o600)
	keylog.Default.SetFiles(path)
	defer keylog.Default.SetFiles()
	f := g.DefaultFlow()
	f.B.Port = 443
	pk := g.TLSCapture(f, writes, 1400)

	// plain HTTP conversation with a form login
	f2 := g.DefaultFlow()
	f2.A.Port = 40100
	hc := g.NewTCPConv(f2, 5e9)
	hc.Send(0, []byte("POST /login HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nuser=bob&password=hunter2!!"))
	hc.Send(1, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"))
	pk = append(pk, hc.Pkts...)

	c, err := store.Open(g.WritePcapng(t, pk))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Load(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	objs, err := export.Objects(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	var jpg *export.Object
	for i := range objs {
		if objs[i].Type == "image/jpeg" {
			jpg = &objs[i]
		}
	}
	if jpg == nil || jpg.Filename != "cat.jpg" || jpg.Size != len(img) || jpg.Proto != "HTTP" {
		t.Fatalf("objects %+v", objs)
	}
	data, err := export.ObjectBytes(c, *jpg)
	if err != nil || !bytes.Equal(data, img) {
		t.Errorf("object bytes: %d err %v", len(data), err)
	}
	dir := t.TempDir()
	if n, err := export.SaveObjects(c, objs, dir); err != nil || n != len(objs) {
		t.Errorf("save %d %v", n, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "cat.jpg")); !bytes.Equal(b, img) {
		t.Error("saved file differs")
	}
	creds, err := export.Credentials(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	var basic, form bool
	for _, cr := range creds {
		if cr.Proto == "HTTP" && cr.Username == "alice" && cr.Password == "secret" {
			basic = true
		}
		if cr.Proto == "HTTP form" && cr.Username == "bob" && cr.Password == "hunter2!!" {
			form = true
		}
	}
	if !basic || !form {
		t.Errorf("credentials %+v", creds)
	}
}

func TestObjectsHTTP3(t *testing.T) {
	f := g.DefaultFlow()
	f.B.Port = 443
	q := g.NewQUICConn(t, f, "h3.example", "h3")
	img := bytes.Repeat([]byte{0xff, 0xd8, 0xff, 0xe0}, 300)
	q.HTTP3Exchange("/pic.jpg", "image/jpeg", img)
	path := filepath.Join(t.TempDir(), "keys")
	os.WriteFile(path, q.Keylog.Bytes(), 0o600)
	keylog.Default.SetFiles(path)
	defer keylog.Default.SetFiles()
	c, err := store.Open(g.WritePcapng(t, q.Packets))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Load(context.Background(), nil)
	objs, err := export.Objects(context.Background(), c)
	if err != nil || len(objs) != 1 || objs[0].Type != "image/jpeg" || objs[0].Filename != "pic.jpg" || objs[0].Proto != "HTTP3" || objs[0].Host != "h3.example" {
		t.Fatalf("%+v %v", objs, err)
	}
	data, err := export.ObjectBytes(c, objs[0])
	if err != nil || !bytes.Equal(data, img) {
		t.Errorf("object bytes: %d %v", len(data), err)
	}
}
