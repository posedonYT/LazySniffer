package pktgen

import (
	"bytes"
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/poseydon/lazysniffer/internal/decrypt"
)

// QUICConn simulates a complete QUIC v1 connection between Go's TLS 1.3
// QUIC client and server and records every packet as a UDP datagram.
// Handshake and 1-RTT packets are really protected, so a capture of it
// needs the key log (Keylog) to be decrypted.
type QUICConn struct {
	t          testing.TB
	Flow       Flow // client → server
	Packets    []Packet
	Keylog     bytes.Buffer
	ts         int64
	dcid0      []byte
	clientCID  []byte
	serverCID  []byte
	keys       [3][2]*decrypt.QUICKeys // [space][direction]
	pn         [3][2]uint64
	cryptoOff  [3][2]uint64
	streamOff  map[[2]uint64]uint64
	serverSeen bool
}

var quicTP = []byte{0x04, 0x04, 0x80, 0x10, 0x00, 0x00, 0x08, 0x02, 0x40, 0x64, 0x01, 0x04, 0x80, 0x00, 0x75, 0x30}

func quicSpace(l tls.QUICEncryptionLevel) int {
	switch l {
	case tls.QUICEncryptionLevelInitial:
		return 0
	case tls.QUICEncryptionLevelHandshake:
		return 1
	}
	return 2
}

// NewQUICConn runs the handshake. serverName is used as SNI and certificate name.
func NewQUICConn(t testing.TB, f Flow, serverName, alpn string) *QUICConn {
	t.Helper()
	q := &QUICConn{t: t, Flow: f, ts: 1e9, streamOff: map[[2]uint64]uint64{},
		dcid0: []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}, clientCID: []byte{0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8},
		serverCID: []byte{0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65}}
	ck, sk, err := decrypt.QUICInitialKeys(decrypt.QUICv1, q.dcid0)
	if err != nil {
		t.Fatal(err)
	}
	q.keys[0][0], q.keys[0][1] = ck, sk
	cert := SelfSigned(t, serverName, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	cli := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS13, NextProtos: []string{alpn},
		InsecureSkipVerify: true, KeyLogWriter: &q.Keylog}})
	srv := tls.QUICServer(&tls.QUICConfig{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{alpn}}})
	if err := cli.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	type flight struct {
		space int
		data  []byte
	}
	pump := func(c *tls.QUICConn, role int) []flight {
		var out []flight
		for {
			ev := c.NextEvent()
			switch ev.Kind {
			case tls.QUICNoEvent:
				return out
			case tls.QUICSetReadSecret:
				k, err := decrypt.QUICKeysFromSecret(decrypt.QUICv1, ev.Suite, ev.Data)
				if err != nil {
					t.Fatal(err)
				}
				q.keys[quicSpace(ev.Level)][1-role] = k
			case tls.QUICSetWriteSecret:
				k, err := decrypt.QUICKeysFromSecret(decrypt.QUICv1, ev.Suite, ev.Data)
				if err != nil {
					t.Fatal(err)
				}
				q.keys[quicSpace(ev.Level)][role] = k
			case tls.QUICWriteData:
				out = append(out, flight{quicSpace(ev.Level), append([]byte(nil), ev.Data...)})
			case tls.QUICTransportParametersRequired:
				c.SetTransportParameters(quicTP)
			}
		}
	}
	emit := func(role int, fl []flight) {
		for _, fv := range fl {
			for off := 0; off < len(fv.data); off += 900 {
				chunk := fv.data[off:min(off+900, len(fv.data))]
				frame := []byte{0x06}
				frame = putVarint(frame, q.cryptoOff[fv.space][role])
				frame = putVarint(frame, uint64(len(chunk)))
				frame = append(frame, chunk...)
				q.cryptoOff[fv.space][role] += uint64(len(chunk))
				q.emit(fv.space, role, frame)
			}
		}
	}
	feed := func(c *tls.QUICConn, fl []flight) {
		for _, fv := range fl {
			level := map[int]tls.QUICEncryptionLevel{0: tls.QUICEncryptionLevelInitial, 1: tls.QUICEncryptionLevelHandshake, 2: tls.QUICEncryptionLevelApplication}[fv.space]
			if err := c.HandleData(level, fv.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	cf := pump(cli, 0)
	emit(0, cf)
	feed(srv, cf)
	sf := pump(srv, 1)
	q.serverSeen = true
	emit(1, sf)
	feed(cli, sf)
	cf = pump(cli, 0)
	emit(0, cf)
	feed(srv, cf)
	sf = pump(srv, 1)
	emit(1, sf)
	feed(cli, sf)
	pump(cli, 0)
	return q
}

// emit builds one packet of a space from dir (0 = client) and stores it as a datagram.
func (q *QUICConn) emit(space, dir int, frames []byte) {
	q.ts += 1e6
	pkt := q.packet(space, dir, frames)
	f := q.Flow
	if dir == 1 {
		f = f.Rev()
	}
	q.Packets = append(q.Packets, Packet{TS: q.ts, Data: UDP(f, pkt)})
}

func (q *QUICConn) packet(space, dir int, frames []byte) []byte {
	keys := q.keys[space][dir]
	if keys == nil {
		q.t.Fatalf("no keys for space %d dir %d", space, dir)
	}
	pn := q.pn[space][dir]
	q.pn[space][dir]++
	const pnLen = 4
	for len(frames) < 4 {
		frames = append(frames, 0) // PADDING: the header protection sample needs 16 bytes
	}
	if space == 0 && dir == 0 {
		for len(frames) < 1162 {
			frames = append(frames, 0)
		}
	}
	var hdr []byte
	dcid, scid := q.serverCID, q.clientCID
	if dir == 1 {
		dcid, scid = q.clientCID, q.serverCID
	}
	if space == 0 && dir == 0 {
		dcid, scid = q.dcid0, q.clientCID
	}
	if dir == 0 && space == 1 {
		dcid, scid = q.serverCID, q.clientCID
	}
	if space == 2 {
		hdr = append(hdr, 0x40|pnLen-1)
		hdr = append(hdr, dcid...)
	} else {
		typ := byte(0)
		if space == 1 {
			typ = 2
		}
		hdr = append(hdr, 0xc0|typ<<4|(pnLen-1), 0, 0, 0, 1, byte(len(dcid)))
		hdr = append(hdr, dcid...)
		hdr = append(hdr, byte(len(scid)))
		hdr = append(hdr, scid...)
		if space == 0 {
			hdr = append(hdr, 0) // token length
		}
		length := uint64(pnLen + len(frames) + 16)
		hdr = append(hdr, 0x40|byte(length>>8), byte(length))
	}
	pnOff := len(hdr)
	hdr = append(hdr, byte(pn>>24), byte(pn>>16), byte(pn>>8), byte(pn))
	ct := keys.AEAD.Seal(pn, hdr, frames)
	pkt := append(append([]byte(nil), hdr...), ct...)
	mask, err := keys.HPC.Mask(pkt[pnOff+4 : pnOff+20])
	if err != nil {
		q.t.Fatal(err)
	}
	if space == 2 {
		pkt[0] ^= mask[0] & 0x1f
	} else {
		pkt[0] ^= mask[0] & 0x0f
	}
	for i := 0; i < pnLen; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}

// SendStream sends a STREAM frame in a 1-RTT packet.
func (q *QUICConn) SendStream(fromClient bool, id uint64, data []byte, fin bool) {
	dir := 1
	if fromClient {
		dir = 0
	}
	key := [2]uint64{uint64(dir), id}
	off := q.streamOff[key]
	typ := byte(0x08 | 0x02)
	if off > 0 {
		typ |= 0x04
	}
	if fin {
		typ |= 0x01
	}
	frame := []byte{typ}
	frame = putVarint(frame, id)
	if off > 0 {
		frame = putVarint(frame, off)
	}
	frame = putVarint(frame, uint64(len(data)))
	frame = append(frame, data...)
	q.streamOff[key] = off + uint64(len(data))
	q.emit(2, dir, frame)
}

// H3Frame builds an HTTP/3 frame.
func H3Frame(typ uint64, payload []byte) []byte {
	b := putVarint(nil, typ)
	b = putVarint(b, uint64(len(payload)))
	return append(b, payload...)
}

// HTTP3Exchange runs one request/response on stream 0 with control streams
// and a QPACK dynamic table entry (x-custom: hello) used by the request.
func (q *QUICConn) HTTP3Exchange(path, contentType string, body []byte) {
	settings := func() []byte {
		var s []byte
		s = putVarint(s, 1) // QPACK_MAX_TABLE_CAPACITY
		s = putVarint(s, 4096)
		s = putVarint(s, 7) // QPACK_BLOCKED_STREAMS
		s = putVarint(s, 16)
		return append([]byte{0x00}, H3Frame(4, s)...) // uni stream type 0 = control
	}
	q.SendStream(true, 2, settings(), false)
	q.SendStream(false, 3, settings(), false)
	// QPACK encoder stream (client): capacity 4096, insert "x-custom: hello"
	enc := []byte{0x02, 0x3f, 0xe1, 0x1f}
	enc = append(enc, 0x48)
	enc = append(enc, "x-custom"...)
	enc = append(enc, 0x05)
	enc = append(enc, "hello"...)
	q.SendStream(true, 6, enc, false)
	// request: RIC=1 (encoded 2), base 1, :method GET, :scheme https, :path, dynamic x-custom
	var blk []byte
	blk = append(blk, 0x02, 0x00, 0xd1, 0xd7)
	blk = append(blk, 0x51, byte(len(path)))
	blk = append(blk, path...)
	blk = append(blk, 0x50, 0x0a) // :authority (static 0) literal name ref
	blk = append(blk, "h3.example"...)
	blk = append(blk, 0x80) // dynamic index 0
	q.SendStream(true, 0, H3Frame(1, blk), true)
	// response: :status 200 (static 25), content-type literal with name reference (static 44), content-length
	var rb []byte
	rb = append(rb, 0x00, 0x00, 0xd9)
	rb = append(rb, 0x5f, 0x1d, byte(len(contentType))) // literal with name reference: static index 44 (15 + 29) is a content-type entry
	rb = append(rb, contentType...)
	q.SendStream(false, 0, append(H3Frame(1, rb), H3Frame(0, body[:len(body)/2])...), false)
	q.SendStream(false, 0, H3Frame(0, body[len(body)/2:]), true)
}
