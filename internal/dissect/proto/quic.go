package proto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/poseydon/lazysniffer/internal/decrypt"
	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	quicFrameTypes = map[uint64]string{0x00: "PADDING", 0x01: "PING", 0x02: "ACK", 0x03: "ACK", 0x04: "RESET_STREAM",
		0x05: "STOP_SENDING", 0x06: "CRYPTO", 0x07: "NEW_TOKEN", 0x10: "MAX_DATA", 0x11: "MAX_STREAM_DATA",
		0x12: "MAX_STREAMS", 0x13: "MAX_STREAMS", 0x14: "DATA_BLOCKED", 0x15: "STREAM_DATA_BLOCKED", 0x16: "STREAMS_BLOCKED",
		0x17: "STREAMS_BLOCKED", 0x18: "NEW_CONNECTION_ID", 0x19: "RETIRE_CONNECTION_ID", 0x1a: "PATH_CHALLENGE",
		0x1b: "PATH_RESPONSE", 0x1c: "CONNECTION_CLOSE", 0x1d: "CONNECTION_CLOSE", 0x1e: "HANDSHAKE_DONE",
		0x30: "DATAGRAM", 0x31: "DATAGRAM", 0xaf: "ACK_FREQUENCY", 0x1f: "IMMEDIATE_ACK"}
	quicLongTypes  = map[uint64]string{0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
	quicErrorCodes = map[uint64]string{0: "NO_ERROR", 1: "INTERNAL_ERROR", 2: "CONNECTION_REFUSED", 3: "FLOW_CONTROL_ERROR",
		4: "STREAM_LIMIT_ERROR", 5: "STREAM_STATE_ERROR", 6: "FINAL_SIZE_ERROR", 7: "FRAME_ENCODING_ERROR",
		8: "TRANSPORT_PARAMETER_ERROR", 9: "CONNECTION_ID_LIMIT_ERROR", 10: "PROTOCOL_VIOLATION", 11: "INVALID_TOKEN",
		12: "APPLICATION_ERROR", 13: "CRYPTO_BUFFER_EXCEEDED", 14: "KEY_UPDATE_ERROR", 15: "AEAD_LIMIT_REACHED", 16: "NO_VIABLE_PATH"}
	quicTPNames = map[uint64]string{0x00: "original_destination_connection_id", 0x01: "max_idle_timeout",
		0x02: "stateless_reset_token", 0x03: "max_udp_payload_size", 0x04: "initial_max_data",
		0x05: "initial_max_stream_data_bidi_local", 0x06: "initial_max_stream_data_bidi_remote",
		0x07: "initial_max_stream_data_uni", 0x08: "initial_max_streams_bidi", 0x09: "initial_max_streams_uni",
		0x0a: "ack_delay_exponent", 0x0b: "max_ack_delay", 0x0c: "disable_active_migration", 0x0d: "preferred_address",
		0x0e: "active_connection_id_limit", 0x0f: "initial_source_connection_id", 0x10: "retry_source_connection_id",
		0x11: "version_information", 0x20: "max_datagram_frame_size", 0x2ab2: "grease_quic_bit",
		0xff73db: "version_information (draft)", 0x3127: "google_connection_options", 0x4752: "google_initial_rtt"}

	protoQUIC      = d.RegisterProto("QUIC IETF", "QUIC", "quic")
	hfQUICHdrForm  = protoQUIC.Field("quic.header_form", "Header Form", d.FtUint8, d.WithMask(0x80), d.WithVS(map[uint64]string{0: "Short Header", 1: "Long Header"}))
	hfQUICFixed    = protoQUIC.Field("quic.fixed_bit", "Fixed Bit", d.FtBool, d.WithMask(0x40), d.WithParentBits(8), d.WithTFS(d.TFSTrue))
	hfQUICLongType = protoQUIC.Field("quic.long.packet_type", "Packet Type", d.FtUint8, d.WithMask(0x30), d.WithVS(quicLongTypes))
	hfQUICLongRes  = protoQUIC.Field("quic.long.reserved", "Reserved", d.FtUint8, d.WithMask(0x0c))
	hfQUICPNLen    = protoQUIC.Field("quic.packet_number_length", "Packet Number Length", d.FtUint8, d.WithMask(0x03), d.WithVS(map[uint64]string{0: "1 bytes", 1: "2 bytes", 2: "3 bytes", 3: "4 bytes"}))
	hfQUICSpin     = protoQUIC.Field("quic.spin_bit", "Spin Bit", d.FtBool, d.WithMask(0x20), d.WithParentBits(8), d.WithTFS(d.TFSTrue))
	hfQUICKeyPhase = protoQUIC.Field("quic.key_phase", "Key Phase Bit", d.FtBool, d.WithMask(0x04), d.WithParentBits(8), d.WithTFS(d.TFSTrue))
	hfQUICVersion  = protoQUIC.Field("quic.version", "Version", d.FtUint32, d.WithBase(d.BaseHex), d.WithVS(quicVersions))
	hfQUICDCIL     = protoQUIC.Field("quic.dcil", "Destination Connection ID Length", d.FtUint8)
	hfQUICDCID     = protoQUIC.Field("quic.dcid", "Destination Connection ID", d.FtBytes)
	hfQUICSCIL     = protoQUIC.Field("quic.scil", "Source Connection ID Length", d.FtUint8)
	hfQUICSCID     = protoQUIC.Field("quic.scid", "Source Connection ID", d.FtBytes)
	hfQUICTokenLen = protoQUIC.Field("quic.token_length", "Token Length", d.FtUint64)
	hfQUICToken    = protoQUIC.Field("quic.token", "Token", d.FtBytes)
	hfQUICLength   = protoQUIC.Field("quic.length", "Length", d.FtUint64)
	hfQUICPN       = protoQUIC.Field("quic.packet_number", "Packet Number", d.FtUint64)
	hfQUICPayload  = protoQUIC.Field("quic.payload", "Payload", d.FtBytes)
	hfQUICProt     = protoQUIC.Field("quic.protected_payload", "Protected Payload", d.FtBytes)
	hfQUICSupVer   = protoQUIC.Field("quic.supported_version", "Supported Version", d.FtUint32, d.WithBase(d.BaseHex), d.WithVS(quicVersions))
	hfQUICRetryTag = protoQUIC.Field("quic.retry_integrity_tag", "Retry Integrity Tag", d.FtBytes)
	hfQUICConnNum  = protoQUIC.Field("quic.connection.number", "Connection Number", d.FtUint32)
	hfQUICFrame    = protoQUIC.Field("quic.frame", "Frame", d.FtNone)
	hfQUICFrameTyp = protoQUIC.Field("quic.frame_type", "Frame Type", d.FtUint64, d.WithVS(quicFrameTypes))
	hfQUICPadLen   = protoQUIC.Field("quic.padding_length", "Padding Length", d.FtUint32)
	hfQUICAckLarg  = protoQUIC.Field("quic.ack.largest_acknowledged", "Largest Acknowledged", d.FtUint64)
	hfQUICAckDelay = protoQUIC.Field("quic.ack.ack_delay", "ACK Delay", d.FtUint64)
	hfQUICAckCount = protoQUIC.Field("quic.ack.ack_range_count", "ACK Range Count", d.FtUint64)
	hfQUICAckFirst = protoQUIC.Field("quic.ack.first_ack_range", "First ACK Range", d.FtUint64)
	hfQUICAckGap   = protoQUIC.Field("quic.ack.gap", "Gap", d.FtUint64)
	hfQUICAckRange = protoQUIC.Field("quic.ack.ack_range", "ACK Range", d.FtUint64)
	hfQUICCryptOff = protoQUIC.Field("quic.crypto.offset", "Offset", d.FtUint64)
	hfQUICCryptLen = protoQUIC.Field("quic.crypto.length", "Length", d.FtUint64)
	hfQUICCryptDat = protoQUIC.Field("quic.crypto.crypto_data", "Crypto Data", d.FtBytes)
	hfQUICStreamID = protoQUIC.Field("quic.stream.stream_id", "Stream ID", d.FtUint64)
	hfQUICStreamOf = protoQUIC.Field("quic.stream.offset", "Offset", d.FtUint64)
	hfQUICStreamLn = protoQUIC.Field("quic.stream.length", "Length", d.FtUint64)
	hfQUICStreamFn = protoQUIC.Field("quic.stream.fin", "Fin", d.FtBool)
	hfQUICStreamDt = protoQUIC.Field("quic.stream_data", "Stream Data", d.FtBytes)
	hfQUICErr      = protoQUIC.Field("quic.cc.error_code", "Error code", d.FtUint64, d.WithVS(quicErrorCodes))
	hfQUICErrApp   = protoQUIC.Field("quic.cc.error_code.app", "Application Error code", d.FtUint64)
	hfQUICErrFrame = protoQUIC.Field("quic.cc.frame_type", "Frame Type", d.FtUint64)
	hfQUICReason   = protoQUIC.Field("quic.cc.reason_phrase", "Reason phrase", d.FtString)
	hfQUICNewCID   = protoQUIC.Field("quic.nci.connection_id", "Connection ID", d.FtBytes)
	hfQUICSeq      = protoQUIC.Field("quic.nci.sequence", "Sequence", d.FtUint64)
	hfQUICMaxData  = protoQUIC.Field("quic.md.maximum_data", "Maximum Data", d.FtUint64)
	hfQUICTP       = protoQUIC.Field("quic.tp.type", "Parameter Type", d.FtUint64, d.WithVS(quicTPNames))
	hfQUICTPLen    = protoQUIC.Field("quic.tp.len", "Length", d.FtUint64)
	hfQUICTPVal    = protoQUIC.Field("quic.tp.value", "Value", d.FtUint64)
	hfQUICTPData   = protoQUIC.Field("quic.tp.data", "Value", d.FtBytes)
	hfQUICDecErr   = protoQUIC.Field("quic.decryption_failed", "Decryption failed", d.FtString)
	eiQUICDecFail  = protoQUIC.Expert("quic.decryption_failed.expert", d.GroupDecryption, d.SevWarn, "Failed to decrypt")
	eiQUICNoKeys   = protoQUIC.Expert("quic.no_keys", d.GroupDecryption, d.SevChat, "No keys to decrypt this packet (set an SSLKEYLOGFILE)")

	quicHandle = d.RegisterHandle("quic", d.NewHandle(protoQUIC, dissectQUIC))
)

func init() {
	for _, p := range []uint64{443, 80, 4433, 8443, 784, 853, 6121} {
		UDPPortTable.Add(p, quicHandle)
	}
	UDPHeur.Add("quic_udp", protoQUIC, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) bool {
		if tvb.Len() < 7 || tvb.U8(0)&0xc0 != 0xc0 {
			return false
		}
		v := uint64(tvb.U32(1))
		if _, ok := quicVersions[v]; !ok && v&0x0f0f0f0f != 0x0a0a0a0a {
			return false
		}
		dissectQUIC(tvb, pi, tree)
		return true
	})
	QUICTransportParams = dissectQUICTransportParams
}

// varint reads a QUIC variable-length integer.
func varint(tvb *d.Tvb, off int) (uint64, int) {
	b := tvb.U8(off)
	n := 1 << (b >> 6)
	v := uint64(b & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(tvb.U8(off+i))
	}
	return v, n
}

type cryptoStream struct {
	delivered uint64
	buf       []byte
	pending   map[uint64][]byte
}

func (c *cryptoStream) add(off uint64, data []byte) [][]byte {
	if c.pending == nil {
		c.pending = map[uint64][]byte{}
	}
	end := off + uint64(len(data))
	if end <= c.delivered {
		return nil
	}
	if off > c.delivered {
		c.pending[off] = append([]byte(nil), data...)
		return nil
	}
	c.buf = append(c.buf, data[c.delivered-off:]...)
	c.delivered = end
	for {
		progressed := false
		for po, pd := range c.pending {
			if po <= c.delivered {
				if pe := po + uint64(len(pd)); pe > c.delivered {
					c.buf = append(c.buf, pd[c.delivered-po:]...)
					c.delivered = pe
				}
				delete(c.pending, po)
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	var msgs [][]byte
	for len(c.buf) >= 4 {
		l := 4 + (int(c.buf[1])<<16 | int(c.buf[2])<<8 | int(c.buf[3]))
		if len(c.buf) < l {
			break
		}
		msgs = append(msgs, append([]byte(nil), c.buf[:l]...))
		c.buf = c.buf[l:]
	}
	return msgs
}

// quicConn is per-connection QUIC state (first pass).
type quicConn struct {
	version   uint32
	origDCID  []byte
	clientCID []byte // client's Source Connection ID
	serverCID []byte // server's Source Connection ID
	client    d.Address
	cport     uint32
	keys      [3][2]*decrypt.QUICKeys // [space][dir]
	largest   [3][2]int64
	crypto    [3][2]*cryptoStream
	Secrets   QUICSecretLookup
	h3        *h3Conn
}

// QUICSecretLookup returns traffic secrets (from a key log) for a connection.
type QUICSecretLookup func(clientRandom []byte, label string) []byte

// QUICKeyLookup is set by the decryption package: it returns the traffic
// secret for a TLS client random and a key log label.
var QUICKeyLookup func(clientRandom []byte, label string) []byte

// quicPkt is stored per QUIC packet in the first pass.
type quicPkt struct {
	first   byte // unprotected first byte
	pn      uint64
	pnLen   int
	plain   []byte // decrypted payload (nil when undecryptable)
	crypto  [][]byte
	decErr  string
	noKeys  bool
	dcidLen int
}

func (q *quicConn) dirOf(pi *d.PacketInfo) int {
	if pi.Src == q.client && pi.SrcPort == q.cport {
		return 0
	}
	return 1
}

func quicConnOf(pi *d.PacketInfo) *quicConn {
	if pi.Conv == nil {
		return &quicConn{}
	}
	q, _ := pi.Conv.Data(protoQUIC).(*quicConn)
	if q == nil {
		q = &quicConn{client: pi.Src, cport: pi.SrcPort}
		for s := range q.largest {
			q.largest[s] = [2]int64{-1, -1}
		}
		if !pi.Visited {
			pi.Conv.SetData(protoQUIC, q)
		}
	}
	return q
}

func decodePN(largest int64, truncated uint64, pnLen int) uint64 {
	expected := uint64(largest + 1)
	win := uint64(1) << (8 * uint(pnLen))
	hwin := win / 2
	mask := win - 1
	cand := (expected &^ mask) | truncated
	switch {
	case cand+hwin <= expected && cand < (1<<62)-win:
		cand += win
	case cand > expected+hwin && cand >= win:
		cand -= win
	}
	return cand
}

func dissectQUIC(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 1 || tvb.U8(0)&0x40 == 0 && tvb.U8(0)&0x80 == 0 {
		return 0
	}
	q := quicConnOf(pi)
	qt := tree.AddProtocol(protoQUIC, tvb, 0, -1)
	pi.SetProtocol("QUIC")
	var infos []string
	idx := 0
	for off := 0; off < tvb.Len(); idx++ {
		n, info := dissectQUICPacket(tvb, off, idx, pi, qt, tree, q)
		if info != "" {
			infos = append(infos, info)
		}
		if n <= 0 {
			break
		}
		off += n
	}
	qt.SetText("QUIC IETF")
	pi.SetInfo(strings.Join(quicFinishInfos(pi, infos), "; "))
	return tvb.Len()
}

func hexs(b []byte) string { return hex.EncodeToString(b) }

func longTypeOf(version uint32, bits uint8) int {
	if version == decrypt.QUICv2 {
		// QUIC v2 renumbers the long header types.
		return map[uint8]int{1: 0, 2: 1, 3: 2, 0: 3}[bits]
	}
	return int(bits)
}

func dissectQUICPacket(tvb *d.Tvb, off, idx int, pi *d.PacketInfo, qt, tree *d.Node, q *quicConn) (int, string) {
	sess := pi.Sess
	key := uint32(idx)
	var rec *quicPkt
	if pi.Visited {
		rec, _ = sess.FrameData(protoQUIC, pi.Num, key).(*quicPkt)
	}
	first := tvb.U8(off)
	dir := q.dirOf(pi)
	if first&0x80 == 0 {
		return dissectQUICShort(tvb, off, idx, pi, qt, q, rec, dir)
	}
	version := tvb.U32(off + 1)
	pt := qt.AddText(tvb, off, tvb.Remaining(off), "QUIC packet")
	if version == 0 {
		pt.SetText("Version Negotiation")
		dcl := int(tvb.U8(off + 5))
		pt.AddUint(hfQUICVersion, tvb, off+1, 4)
		p := off + 6 + dcl
		scl := int(tvb.U8(p))
		pt.AddBytes(hfQUICDCID, tvb, off+6, dcl)
		pt.AddBytes(hfQUICSCID, tvb, p+1, scl)
		for v := p + 1 + scl; v+4 <= tvb.Len(); v += 4 {
			pt.AddUint(hfQUICSupVer, tvb, v, 4)
		}
		return tvb.Len() - off, "Version Negotiation"
	}
	ltype := longTypeOf(version, (first>>4)&3)
	tname := quicLongTypes[uint64(ltype)]
	pt.AddBits(hfQUICHdrForm, tvb, off, 1, uint64(first))
	pt.AddBits(hfQUICFixed, tvb, off, 1, uint64(first))
	pt.AddUintValue(hfQUICLongType, tvb, off, 1, uint64(ltype)).SetText("..%02b .... = Packet Type: %s (%d)", (first>>4)&3, tname, ltype)
	pt.AddUint(hfQUICVersion, tvb, off+1, 4)
	p := off + 5
	dcl := int(tvb.U8(p))
	pt.AddUint(hfQUICDCIL, tvb, p, 1)
	_, dcid := pt.AddBytes(hfQUICDCID, tvb, p+1, dcl)
	p += 1 + dcl
	scl := int(tvb.U8(p))
	pt.AddUint(hfQUICSCIL, tvb, p, 1)
	_, scid := pt.AddBytes(hfQUICSCID, tvb, p+1, scl)
	p += 1 + scl
	if !pi.Visited {
		if q.version == 0 {
			q.version = version
		}
		if ltype == 0 && dir == 0 && q.origDCID == nil {
			q.origDCID = append([]byte(nil), dcid...)
		}
		if dir == 0 {
			q.clientCID = append([]byte(nil), scid...)
		} else if ltype != 3 {
			q.serverCID = append([]byte(nil), scid...)
		}
	}
	info := fmt.Sprintf("%s, DCID=%s", tname, hexs(dcid))
	if scl > 0 {
		info += ", SCID=" + hexs(scid)
	}
	pt.SetText("QUIC IETF: %s", tname)
	if ltype == 3 {
		tl := tvb.Remaining(p) - 16
		if tl > 0 {
			pt.AddBytes(hfQUICToken, tvb, p, tl)
		}
		pt.AddBytes(hfQUICRetryTag, tvb, p+max(tl, 0), min(16, tvb.Remaining(p)))
		return tvb.Len() - off, "Retry, " + info
	}
	if ltype == 0 {
		tl, n := varint(tvb, p)
		pt.AddUintValue(hfQUICTokenLen, tvb, p, n, tl)
		p += n
		if tl > 0 {
			pt.AddBytes(hfQUICToken, tvb, p, int(tl))
		}
		p += int(tl)
	}
	length, n := varint(tvb, p)
	pt.AddUintValue(hfQUICLength, tvb, p, n, length)
	p += n
	pnOff := p
	end := min(pnOff+int(length), tvb.Len())
	pt.SetLen(end - off)
	space := map[int]int{0: 0, 1: 2, 2: 1}[ltype] // 0-RTT uses the application space
	if rec == nil {
		rec = &quicPkt{}
		if !pi.Visited {
			var keys *decrypt.QUICKeys
			switch {
			case ltype == 0 && decrypt.QUICSupported(version) && q.origDCID != nil:
				if q.keys[0][0] == nil {
					c, s, err := decrypt.QUICInitialKeys(version, q.origDCID)
					if err == nil {
						q.keys[0][0], q.keys[0][1] = c, s
					}
				}
				keys = q.keys[0][dir]
			default:
				keys = q.keysFor(pi, space, dir, ltype == 1)
			}
			q.unprotect(tvb.Raw()[off:end], pnOff-off, keys, space, dir, rec, 0x0f)
			sess.SetFrameData(protoQUIC, pi.Num, key, rec)
		}
	}
	return end - off, quicShowPacket(tvb, off, pnOff, end, pi, pt, tree, q, rec, info, space, dir, idx)
}

// keysFor returns Handshake/1-RTT keys from the key log, when available.
func (q *quicConn) keysFor(pi *d.PacketInfo, space, dir int, zeroRTT bool) *decrypt.QUICKeys {
	if k := q.keys[space][dir]; k != nil {
		return k
	}
	if QUICKeyLookup == nil {
		return nil
	}
	ts, _ := pi.Conv.Data(protoTLS).(*tlsSession)
	if ts == nil || ts.clientRandom == nil {
		return nil
	}
	label := map[[2]int]string{{1, 0}: "CLIENT_HANDSHAKE_TRAFFIC_SECRET", {1, 1}: "SERVER_HANDSHAKE_TRAFFIC_SECRET",
		{2, 0}: "CLIENT_TRAFFIC_SECRET_0", {2, 1}: "SERVER_TRAFFIC_SECRET_0"}[[2]int{space, dir}]
	if zeroRTT {
		label = "CLIENT_EARLY_TRAFFIC_SECRET"
	}
	secret := QUICKeyLookup(ts.clientRandom, label)
	if secret == nil {
		return nil
	}
	suite := ts.cipher
	if suite == 0 {
		suite = 0x1301
	}
	k, err := decrypt.QUICKeysFromSecret(q.version, suite, secret)
	if err != nil {
		return nil
	}
	q.keys[space][dir] = k
	return k
}

// unprotect removes header protection and decrypts a packet (first pass).
func (q *quicConn) unprotect(pkt []byte, pnOff int, keys *decrypt.QUICKeys, space, dir int, rec *quicPkt, firstMask byte) {
	rec.first = pkt[0]
	if keys == nil {
		rec.noKeys = true
		return
	}
	if pnOff+4+16 > len(pkt) {
		rec.decErr = "packet too short for a header protection sample"
		return
	}
	mask, err := keys.HPC.Mask(pkt[pnOff+4 : pnOff+20])
	if err != nil {
		rec.decErr = err.Error()
		return
	}
	hdr := append([]byte(nil), pkt[:pnOff+4]...)
	hdr[0] ^= mask[0] & firstMask
	pnLen := int(hdr[0]&3) + 1
	var trunc uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOff+i] ^= mask[1+i]
		trunc = trunc<<8 | uint64(hdr[pnOff+i])
	}
	hdr = hdr[:pnOff+pnLen]
	pn := decodePN(q.largest[space][dir], trunc, pnLen)
	plain, err := keys.AEAD.Open(pn, hdr, pkt[pnOff+pnLen:])
	rec.first, rec.pn, rec.pnLen = hdr[0], pn, pnLen
	if err != nil {
		rec.decErr = "AEAD authentication failed (wrong keys?)"
		return
	}
	if int64(pn) > q.largest[space][dir] {
		q.largest[space][dir] = int64(pn)
	}
	rec.plain = plain
	// Collect CRYPTO data for the TLS handshake.
	if q.crypto[space][dir] == nil {
		q.crypto[space][dir] = &cryptoStream{}
	}
	ptvb := d.NewTvb(plain, len(plain), 0)
	func() {
		defer func() { recover() }()
		for p := 0; p < len(plain); {
			ft, n := varint(ptvb, p)
			p += n
			switch {
			case ft == 0x06:
				co, n1 := varint(ptvb, p)
				cl, n2 := varint(ptvb, p+n1)
				data := ptvb.Bytes(p+n1+n2, int(cl))
				rec.crypto = append(rec.crypto, q.crypto[space][dir].add(co, data)...)
				p += n1 + n2 + int(cl)
			default:
				np := skipQUICFrame(ptvb, p, ft)
				if np < 0 {
					return
				}
				p = np
			}
		}
	}()
}

// skipQUICFrame returns the offset after a frame body (or -1 if unknown).
func skipQUICFrame(t *d.Tvb, p int, ft uint64) int {
	v := func() uint64 { x, n := varint(t, p); p += n; return x }
	switch {
	case ft == 0x00 || ft == 0x01 || ft == 0x1e || ft == 0x1f:
	case ft == 0x02 || ft == 0x03:
		v()
		v()
		c := v()
		v()
		for i := uint64(0); i < c; i++ {
			v()
			v()
		}
		if ft == 0x03 {
			v()
			v()
			v()
		}
	case ft == 0x04:
		v()
		v()
		v()
	case ft == 0x05:
		v()
		v()
	case ft == 0x07:
		l := v()
		p += int(l)
	case ft >= 0x08 && ft <= 0x0f:
		v()
		if ft&0x04 != 0 {
			v()
		}
		l := uint64(t.Remaining(p))
		if ft&0x02 != 0 {
			l = v()
		}
		p += int(l)
	case ft >= 0x10 && ft <= 0x17:
		v()
		if ft == 0x11 || ft == 0x15 {
			v()
		}
	case ft == 0x18:
		v()
		v()
		l := int(t.U8(p))
		p += 1 + l + 16
	case ft == 0x19:
		v()
	case ft == 0x1a || ft == 0x1b:
		p += 8
	case ft == 0x1c || ft == 0x1d:
		v()
		if ft == 0x1c {
			v()
		}
		l := v()
		p += int(l)
	case ft == 0x30 || ft == 0x31:
		l := uint64(t.Remaining(p))
		if ft == 0x31 {
			l = v()
		}
		p += int(l)
	default:
		return -1
	}
	return p
}

func quicShowPacket(tvb *d.Tvb, off, pnOff, end int, pi *d.PacketInfo, pt, tree *d.Node, q *quicConn, rec *quicPkt, info string, space, dir, idx int) string {
	if rec.plain == nil {
		pt.AddBytes(hfQUICProt, tvb, pnOff, end-pnOff)
		switch {
		case rec.noKeys:
			pt.AddExpert(eiQUICNoKeys, "")
		case rec.decErr != "":
			pt.AddGenerated(hfQUICDecErr, d.StringValue(rec.decErr)).AddExpert(eiQUICDecFail, "Failed to decrypt: %s", rec.decErr)
		}
		return info
	}
	first := uint64(rec.first)
	pt.AddUintValue(hfQUICLongRes, tvb, off, 1, (first>>2)&3)
	pt.AddUintValue(hfQUICPNLen, tvb, off, 1, first&3).SetText(".... ..%02b = Packet Number Length: %d bytes (%d)", first&3, rec.pnLen, first&3)
	pt.AddUintValue(hfQUICPN, tvb, pnOff, rec.pnLen, rec.pn)
	src := pi.AddSource("Decrypted QUIC", rec.plain)
	pt.AddBytes(hfQUICPayload, tvb, pnOff+rec.pnLen, end-pnOff-rec.pnLen)
	frames := dissectQUICFrames(src, pi, pt, q, dir, idx)
	info += fmt.Sprintf(", PKN: %d", rec.pn)
	if len(frames) > 0 {
		info += ", " + strings.Join(frames, ", ")
	}
	if len(rec.crypto) > 0 {
		sess, tdir := tlsSessionOf(pi)
		_ = dir
		var all []byte
		for _, m := range rec.crypto {
			all = append(all, m...)
		}
		ct := pi.AddSource("Reassembled QUIC CRYPTO", all)
		tt := pt.AddProtocol(protoTLS, ct, 0, ct.Len())
		tt.SetText("TLSv1.3 Record Layer: Handshake Protocol")
		var dummy []string
		var names []string
		for p := 0; p < ct.Len(); {
			ml := 4 + int(ct.U24(p+1))
			names = append(names, dissectHandshakeMsg(ct.Sub(p, ml), pi, tt, sess, tdir, "q", &dummy))
			p += ml
		}
		tt.SetText("TLSv1.3 Record Layer: Handshake Protocol: %s", strings.Join(names, ", "))
	}
	return info
}

func dissectQUICShort(tvb *d.Tvb, off, idx int, pi *d.PacketInfo, qt *d.Node, q *quicConn, rec *quicPkt, dir int) (int, string) {
	first := tvb.U8(off)
	pt := qt.AddText(tvb, off, tvb.Remaining(off), "QUIC Short Header")
	pt.AddBits(hfQUICHdrForm, tvb, off, 1, uint64(first))
	pt.AddBits(hfQUICFixed, tvb, off, 1, uint64(first))
	pt.AddBits(hfQUICSpin, tvb, off, 1, uint64(first))
	cid := q.serverCID
	if dir == 1 {
		cid = q.clientCID
	}
	dcl := len(cid)
	if dcl > tvb.Remaining(off+1) {
		dcl = 0
	}
	_, dcid := pt.AddBytes(hfQUICDCID, tvb, off+1, dcl)
	pnOff := off + 1 + dcl
	if rec == nil {
		rec = &quicPkt{}
		if !pi.Visited {
			keys := q.keysFor(pi, 2, dir, false)
			q.unprotect(tvb.Raw()[off:], pnOff-off, keys, 2, dir, rec, 0x1f)
			pi.Sess.SetFrameData(protoQUIC, pi.Num, uint32(idx), rec)
		}
	}
	var kp byte // the key phase bit is header protected: unknown without keys
	if rec.plain != nil {
		kp = (rec.first >> 2) & 1
	}
	info := fmt.Sprintf("Protected Payload (KP%d), DCID=%s", kp, hexs(dcid))
	if rec.plain == nil {
		pt.AddBytes(hfQUICProt, tvb, pnOff, tvb.Remaining(pnOff))
		if rec.noKeys {
			pt.AddExpert(eiQUICNoKeys, "")
		}
		return tvb.Len() - off, info
	}
	pt.AddBits(hfQUICKeyPhase, tvb, off, 1, uint64(rec.first))
	pt.AddUintValue(hfQUICPN, tvb, pnOff, rec.pnLen, rec.pn)
	src := pi.AddSource("Decrypted QUIC", rec.plain)
	frames := dissectQUICFrames(src, pi, pt, q, dir, idx)
	info = fmt.Sprintf("Protected Payload (KP%d), DCID=%s, PKN: %d", kp, hexs(dcid), rec.pn)
	if len(frames) > 0 {
		info += ", " + strings.Join(frames, ", ")
	}
	return tvb.Len() - off, info
}

// quicUsesH3 tells whether the connection negotiated HTTP/3.
func quicUsesH3(pi *d.PacketInfo) bool {
	ts, _ := pi.Conv.Data(protoTLS).(*tlsSession)
	if ts == nil {
		return false
	}
	if strings.HasPrefix(ts.alpn, "h3") {
		return true
	}
	for _, a := range ts.clientALPN {
		if strings.HasPrefix(a, "h3") {
			return ts.alpn == ""
		}
	}
	return false
}

func dissectQUICFrames(t *d.Tvb, pi *d.PacketInfo, pt *d.Node, q *quicConn, dir, pktIdx int) []string {
	var names []string
	var h3Infos []string
	p := 0
	frameNo := 0
	for p < t.Len() {
		frameNo++
		start := p
		ft, n := varint(t, p)
		name := quicFrameTypes[ft]
		if ft >= 0x08 && ft <= 0x0f {
			name = "STREAM"
		}
		if name == "" {
			name = fmt.Sprintf("Unknown (0x%x)", ft)
		}
		fn := pt.AddValue(hfQUICFrame, t, p, 1, d.Value{})
		fn.AddUintValue(hfQUICFrameTyp, t, p, n, ft)
		p += n
		v := func(hf *d.FieldDef) uint64 {
			x, k := varint(t, p)
			fn.AddUintValue(hf, t, p, k, x)
			p += k
			return x
		}
		label := name
		switch {
		case ft == 0x00:
			for p < t.Len() && t.U8(p) == 0 {
				p++
			}
			fn.AddUintValue(hfQUICPadLen, t, start, p-start, uint64(p-start))
			label = fmt.Sprintf("PADDING Length: %d", p-start)
		case ft == 0x02 || ft == 0x03:
			la := v(hfQUICAckLarg)
			v(hfQUICAckDelay)
			c := v(hfQUICAckCount)
			v(hfQUICAckFirst)
			for i := uint64(0); i < c && p < t.Len(); i++ {
				v(hfQUICAckGap)
				v(hfQUICAckRange)
			}
			if ft == 0x03 {
				for i := 0; i < 3; i++ {
					x, k := varint(t, p)
					_ = x
					p += k
				}
			}
			label = fmt.Sprintf("ACK LA: %d", la)
		case ft == 0x06:
			co := v(hfQUICCryptOff)
			cl := v(hfQUICCryptLen)
			fn.AddBytes(hfQUICCryptDat, t, p, int(cl))
			p += int(cl)
			label = fmt.Sprintf("CRYPTO Offset: %d, Length: %d", co, cl)
		case ft >= 0x08 && ft <= 0x0f:
			sid := v(hfQUICStreamID)
			var so uint64
			if ft&0x04 != 0 {
				so = v(hfQUICStreamOf)
			}
			l := uint64(t.Remaining(p))
			if ft&0x02 != 0 {
				l = v(hfQUICStreamLn)
			}
			fin := ft&1 != 0
			fn.AddValue(hfQUICStreamFn, nil, 0, 0, d.BoolValue(fin))
			fn.AddBytes(hfQUICStreamDt, t, p, int(l))
			if pi.Conv != nil && q != nil && quicUsesH3(pi) {
				key := 0x10000 + uint32(pktIdx)*0x100 + uint32(frameNo)
				var recs []*h3Rec
				if pi.Visited {
					recs, _ = pi.Sess.FrameData(protoQUIC, pi.Num, key).([]*h3Rec)
				} else {
					if q.h3 == nil {
						q.h3 = newH3Conn()
					}
					recs = q.h3.feed(dir, sid, so, t.Bytes(p, int(l)), fin)
					pi.Sess.SetFrameData(protoQUIC, pi.Num, key, recs)
				}
				h3Infos = h3Show(fn, pi, recs)
			}
			p += int(l)
			label = fmt.Sprintf("STREAM(%d)", sid)
			name = label
			if len(h3Infos) > 0 {
				name = "\x00H3:" + strings.Join(h3Infos, ", ")
				h3Infos = nil
			}
		case ft == 0x1c || ft == 0x1d:
			if ft == 0x1c {
				v(hfQUICErr)
				v(hfQUICErrFrame)
			} else {
				v(hfQUICErrApp)
			}
			rl, k := varint(t, p)
			p += k
			fn.AddString(hfQUICReason, t, p, int(rl))
			p += int(rl)
		case ft == 0x18:
			v(hfQUICSeq)
			x, k := varint(t, p)
			_ = x
			p += k
			l := int(t.U8(p))
			fn.AddBytes(hfQUICNewCID, t, p+1, l)
			p += 1 + l + 16
		case ft == 0x10:
			v(hfQUICMaxData)
		default:
			np := skipQUICFrame(t, p, ft)
			if np < 0 {
				fn.SetLen(t.Len() - start)
				fn.SetText("%s", label)
				names = append(names, name)
				return names
			}
			p = np
		}
		fn.SetLen(p - start)
		fn.SetText("%s", label)
		if len(names) == 0 || names[len(names)-1] != name {
			names = append(names, name)
		}
	}
	return names
}

func dissectQUICTransportParams(ev *d.Tvb, en *d.Node) {
	for p := 0; p < ev.Len(); {
		id, n1 := varint(ev, p)
		l, n2 := varint(ev, p+n1)
		name := quicTPNames[id]
		if name == "" {
			if id&0x1f == 0x1b && id > 0x1f {
				name = "GREASE"
			} else {
				name = fmt.Sprintf("Unknown 0x%x", id)
			}
		}
		pn := en.AddText(ev, p, n1+n2+int(l), "Parameter: %s (len=%d)", name, l)
		pn.AddUintValue(hfQUICTP, ev, p, n1, id)
		pn.AddUintValue(hfQUICTPLen, ev, p+n1, n2, l)
		vo := p + n1 + n2
		switch id {
		case 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x20:
			if l > 0 {
				x, _ := varint(ev, vo)
				pn.AddUintValue(hfQUICTPVal, ev, vo, int(l), x)
				pn.AppendText(" %d", x)
			}
		default:
			if l > 0 {
				pn.AddBytes(hfQUICTPData, ev, vo, int(l))
			}
		}
		p = vo + int(l)
	}
}

var _ = bytes.Equal

// quicFinishInfos lets HTTP/3 take over the Protocol and Info columns when
// the datagram carries nothing but HTTP/3 stream data, like Wireshark.
func quicFinishInfos(pi *d.PacketInfo, infos []string) []string {
	h3only := len(infos) > 0
	var out []string
	for _, in := range infos {
		if i := strings.Index(in, "\x00H3:"); i >= 0 {
			out = append(out, in[i+4:])
			continue
		}
		h3only = false
		out = append(out, in)
	}
	if h3only {
		pi.SetProtocol("HTTP3")
		return []string{strings.Join(out, ", ")}
	}
	for i, in := range out {
		out[i] = strings.ReplaceAll(in, "\x00H3:", "")
	}
	return out
}
