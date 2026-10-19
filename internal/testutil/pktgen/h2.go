package pktgen

import (
	"bytes"
	"compress/gzip"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// HTTP2Bytes returns the client and server byte streams of two HTTP/2 requests (h2c prior knowledge).
func HTTP2Bytes() ([]byte, []byte) {
	var cli, srv bytes.Buffer
	cli.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	cf := http2.NewFramer(&cli, nil)
	sf := http2.NewFramer(&srv, nil)
	cf.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100})
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{{":method", "GET"}, {":scheme", "http"}, {":authority", "media.example"}, {":path", "/pic.jpg"}, {"user-agent", "lab4"}} {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	cf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: append([]byte(nil), hb.Bytes()...), EndStream: true, EndHeaders: true})
	// second request reuses the HPACK dynamic table
	hb.Reset()
	for _, f := range [][2]string{{":method", "GET"}, {":scheme", "http"}, {":authority", "media.example"}, {":path", "/movie.mp4"}, {"user-agent", "lab4"}} {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	cf.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: append([]byte(nil), hb.Bytes()...), EndStream: true, EndHeaders: true})

	sf.WriteSettings()
	sf.WriteSettingsAck()
	hb.Reset()
	senc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{{":status", "200"}, {"content-type", "image/jpeg"}, {"content-length", "10"}} {
		senc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	sf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: append([]byte(nil), hb.Bytes()...), EndHeaders: true})
	sf.WriteData(1, false, []byte("\xff\xd8\xff\xe0JF"))
	sf.WriteData(1, true, []byte("IF\x00\x01"))
	hb.Reset()
	for _, f := range [][2]string{{":status", "200"}, {"content-type", "text/plain"}, {"content-encoding", "gzip"}} {
		senc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	sf.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: append([]byte(nil), hb.Bytes()...), EndHeaders: true})
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("hello video world"))
	zw.Close()
	sf.WriteData(3, true, gz.Bytes())

	return cli.Bytes(), srv.Bytes()
}

// SampleHTTP2 is an h2c exchange on the given server port.
func SampleHTTP2(port uint16) []Packet {
	cli, srv := HTTP2Bytes()
	f := DefaultFlow()
	f.B.Port = port
	c := NewTCPConv(f, 1e9)
	c.Send(0, cli)
	c.Send(1, srv)
	c.Close()
	return c.Pkts
}
