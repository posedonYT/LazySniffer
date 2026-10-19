package pktgen

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/poseydon/lazysniffer/internal/decrypt"
)

func putVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, 0x40|byte(v>>8), byte(v))
	default:
		return append(b, 0x80|byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// QUICClientHello returns the Initial-level CRYPTO bytes of a Go QUIC
// client (a real TLS 1.3 ClientHello with QUIC transport parameters).
func QUICClientHello(t testing.TB, serverName string) []byte {
	t.Helper()
	conn := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{
		ServerName: serverName, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, InsecureSkipVerify: true,
	}})
	if err := conn.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var out []byte
	for {
		ev := conn.NextEvent()
		if ev.Kind == tls.QUICNoEvent {
			break
		}
		if ev.Kind == tls.QUICTransportParametersRequired {
			// initial_max_data=1048576, initial_max_streams_bidi=100, max_idle_timeout=30000
			conn.SetTransportParameters([]byte{0x04, 0x04, 0x80, 0x10, 0x00, 0x00, 0x08, 0x02, 0x40, 0x64, 0x01, 0x04, 0x80, 0x00, 0x75, 0x30})
		}
		if ev.Kind == tls.QUICWriteData && ev.Level == tls.QUICEncryptionLevelInitial {
			out = append(out, ev.Data...)
		}
	}
	conn.Close()
	return out
}

// QUICInitial builds a protected QUIC v1 Initial packet carrying a CRYPTO
// frame (and PADDING up to 1200 bytes) from client to server.
func QUICInitial(t testing.TB, version uint32, dcid, scid []byte, pn uint32, cryptoOff uint64, crypto []byte, fromClient bool) []byte {
	t.Helper()
	ck, sk, err := decrypt.QUICInitialKeys(version, dcid)
	if err != nil {
		t.Fatal(err)
	}
	keys := sk
	if fromClient {
		keys = ck
	}
	var frames []byte
	frames = append(frames, 0x06)
	frames = putVarint(frames, cryptoOff)
	frames = putVarint(frames, uint64(len(crypto)))
	frames = append(frames, crypto...)
	pnLen := 4
	for len(frames)+pnLen+16 < 1162 {
		frames = append(frames, 0)
	}
	typ := byte(0) // v1 Initial
	if version == decrypt.QUICv2 {
		typ = 1
	}
	hdr := []byte{0xc0 | typ<<4 | byte(pnLen-1)}
	hdr = append(hdr, byte(version>>24), byte(version>>16), byte(version>>8), byte(version))
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = putVarint(hdr, 0) // token length
	length := uint64(pnLen + len(frames) + 16)
	hdr = append(hdr, 0x40|byte(length>>8), byte(length))
	pnOff := len(hdr)
	hdr = append(hdr, byte(pn>>24), byte(pn>>16), byte(pn>>8), byte(pn))
	ct := keys.AEAD.Seal(uint64(pn), hdr, frames)
	pkt := append(append([]byte(nil), hdr...), ct...)
	mask, err := keys.HPC.Mask(pkt[pnOff+4 : pnOff+20])
	if err != nil {
		t.Fatal(err)
	}
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}
