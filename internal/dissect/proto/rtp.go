package proto

import (
	"fmt"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var rtpPayloadTypes = map[uint64]string{0: "ITU-T G.711 PCMU", 3: "GSM 06.10", 4: "ITU-T G.723", 5: "DVI4 8000", 6: "DVI4 16000", 7: "LPC",
	8: "ITU-T G.711 PCMA", 9: "ITU-T G.722", 10: "L16 stereo", 11: "L16 mono", 13: "Comfort noise", 14: "MPEG-I/II Audio", 15: "G.728",
	18: "ITU-T G.729", 26: "JPEG", 31: "H.261", 32: "MPEG-I/II Video", 33: "MPEG-II transport stream", 34: "H.263",
	101: "telephone-event (dynamic)", 96: "DynamicRTP-Type-96", 97: "DynamicRTP-Type-97", 98: "DynamicRTP-Type-98", 99: "DynamicRTP-Type-99",
	100: "DynamicRTP-Type-100", 102: "DynamicRTP-Type-102", 103: "DynamicRTP-Type-103", 111: "DynamicRTP-Type-111", 126: "DynamicRTP-Type-126"}

var (
	protoRTP    = d.RegisterProto("Real-Time Transport Protocol", "RTP", "rtp")
	hfRTPVer    = protoRTP.Field("rtp.version", "Version", d.FtUint8, d.WithMask(0xc0), d.WithParentBits(8))
	hfRTPPad    = protoRTP.Field("rtp.padding", "Padding", d.FtBool, d.WithMask(0x20), d.WithParentBits(8))
	hfRTPExt    = protoRTP.Field("rtp.ext", "Extension", d.FtBool, d.WithMask(0x10), d.WithParentBits(8))
	hfRTPCC     = protoRTP.Field("rtp.cc", "Contributing source identifiers count", d.FtUint8, d.WithMask(0x0f), d.WithParentBits(8))
	hfRTPMarker = protoRTP.Field("rtp.marker", "Marker", d.FtBool, d.WithMask(0x80), d.WithParentBits(8))
	hfRTPPT     = protoRTP.Field("rtp.p_type", "Payload type", d.FtUint8, d.WithMask(0x7f), d.WithParentBits(8), d.WithVS(rtpPayloadTypes))
	hfRTPSeq    = protoRTP.Field("rtp.seq", "Sequence number", d.FtUint16)
	hfRTPTS     = protoRTP.Field("rtp.timestamp", "Timestamp", d.FtUint32)
	hfRTPSSRC   = protoRTP.Field("rtp.ssrc", "Synchronization Source identifier", d.FtUint32, d.WithBase(d.BaseHex))
	hfRTPCSRC   = protoRTP.Field("rtp.csrc.item", "CSRC item", d.FtUint32, d.WithBase(d.BaseHex))
	hfRTPPay    = protoRTP.Field("rtp.payload", "Payload", d.FtBytes)
	hfRTPSetup  = protoRTP.Field("rtp.setup-frame", "Setup frame", d.FtFrameNum)
	hfRTPExtID  = protoRTP.Field("rtp.ext.profile", "Defined by profile", d.FtUint16, d.WithBase(d.BaseHex))
	rtpHandle   = d.RegisterHandle("rtp", d.NewHandle(protoRTP, dissectRTP))

	rtcpTypes = map[uint64]string{200: "Sender Report", 201: "Receiver Report", 202: "Source description", 203: "Goodbye", 204: "Application defined",
		205: "Generic RTP Feedback", 206: "Payload-specific Feedback", 207: "Extended report"}
	protoRTCP    = d.RegisterProto("Real-time Transport Control Protocol", "RTCP", "rtcp")
	hfRTCPVer    = protoRTCP.Field("rtcp.version", "Version", d.FtUint8, d.WithMask(0xc0), d.WithParentBits(8))
	hfRTCPPad    = protoRTCP.Field("rtcp.padding", "Padding", d.FtBool, d.WithMask(0x20), d.WithParentBits(8))
	hfRTCPCount  = protoRTCP.Field("rtcp.rc", "Reception report count", d.FtUint8, d.WithMask(0x1f), d.WithParentBits(8))
	hfRTCPPT     = protoRTCP.Field("rtcp.pt", "Packet type", d.FtUint8, d.WithVS(rtcpTypes))
	hfRTCPLen    = protoRTCP.Field("rtcp.length", "Length", d.FtUint16)
	hfRTCPSSRC   = protoRTCP.Field("rtcp.senderssrc", "Sender SSRC", d.FtUint32, d.WithBase(d.BaseHex))
	hfRTCPNTPMSW = protoRTCP.Field("rtcp.timestamp.ntp.msw", "Timestamp, MSW", d.FtUint32)
	hfRTCPNTPLSW = protoRTCP.Field("rtcp.timestamp.ntp.lsw", "Timestamp, LSW", d.FtUint32)
	hfRTCPRTPTS  = protoRTCP.Field("rtcp.timestamp.rtp", "RTP timestamp", d.FtUint32)
	hfRTCPPkts   = protoRTCP.Field("rtcp.sender.packetcount", "Sender's packet count", d.FtUint32)
	hfRTCPOct    = protoRTCP.Field("rtcp.sender.octetcount", "Sender's octet count", d.FtUint32)
	hfRTCPRBSSRC = protoRTCP.Field("rtcp.ssrc.source", "Identifier", d.FtUint32, d.WithBase(d.BaseHex))
	hfRTCPFrac   = protoRTCP.Field("rtcp.ssrc.fraction", "Fraction lost", d.FtUint8)
	hfRTCPLost   = protoRTCP.Field("rtcp.ssrc.cum_nr", "Cumulative number of packets lost", d.FtInt32)
	hfRTCPHigh   = protoRTCP.Field("rtcp.ssrc.ext_high", "Extended highest sequence number received", d.FtUint32)
	hfRTCPJit    = protoRTCP.Field("rtcp.ssrc.jitter", "Interarrival jitter", d.FtUint32)
	hfRTCPSDES   = protoRTCP.Field("rtcp.sdes.text", "Text", d.FtString)
	hfRTCPCNAME  = protoRTCP.Field("rtcp.sdes.cname", "CNAME", d.FtString)
	rtcpHandle   = d.RegisterHandle("rtcp", d.NewHandle(protoRTCP, dissectRTCP))
)

// rtpFor tells whether the packet belongs to a media stream announced in SDP,
// and whether it is RTCP (odd port or RTCP payload type).
func rtpFor(pi *d.PacketInfo, payload *d.Tvb) (setup uint32, rtcp bool, ok bool) {
	rs, _ := pi.Sess.ProtoState(protoRTP).(*rtpExpect)
	if rs == nil || len(rs.endpoints) == 0 {
		return 0, false, false
	}
	for _, k := range []string{fmt.Sprintf("%s:%d", pi.Dst, pi.DstPort), fmt.Sprintf("%s:%d", pi.Src, pi.SrcPort)} {
		if f, found := rs.endpoints[k]; found {
			setup, ok = f, true
		}
	}
	if !ok || payload.Len() < 8 {
		return 0, false, false
	}
	b0, b1 := payload.U8(0), payload.U8(1)
	if b0>>6 != 2 {
		return 0, false, false
	}
	if b1 >= 192 && b1 <= 223 {
		rtcp = true
	}
	return setup, rtcp, true
}

func looksLikeRTP(tvb *d.Tvb) bool {
	return tvb.Len() >= 12 && tvb.U8(0)>>6 == 2 && tvb.U8(1)&0x7f != 72 && !(tvb.U8(1) >= 192 && tvb.U8(1) <= 223)
}

func dissectRTP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if !looksLikeRTP(tvb) {
		return 0
	}
	rt := tree.AddProtocol(protoRTP, tvb, 0, -1)
	pi.SetProtocol("RTP")
	b0 := uint64(tvb.U8(0))
	rt.AddBits(hfRTPVer, tvb, 0, 1, b0)
	rt.AddBits(hfRTPPad, tvb, 0, 1, b0)
	rt.AddBits(hfRTPExt, tvb, 0, 1, b0)
	rt.AddBits(hfRTPCC, tvb, 0, 1, b0)
	b1 := uint64(tvb.U8(1))
	rt.AddBits(hfRTPMarker, tvb, 1, 1, b1)
	rt.AddBits(hfRTPPT, tvb, 1, 1, b1)
	_, seq := rt.AddUint(hfRTPSeq, tvb, 2, 2)
	_, ts := rt.AddUint(hfRTPTS, tvb, 4, 4)
	_, ssrc := rt.AddUint(hfRTPSSRC, tvb, 8, 4)
	off := 12
	for i := 0; i < int(b0&0x0f) && tvb.Has(off, 4); i++ {
		rt.AddUint(hfRTPCSRC, tvb, off, 4)
		off += 4
	}
	if b0&0x10 != 0 && tvb.Has(off, 4) {
		rt.AddUint(hfRTPExtID, tvb, off, 2)
		off += 4 + int(tvb.U16(off+2))*4
	}
	end := tvb.Len()
	if b0&0x20 != 0 && end > off {
		end -= int(tvb.U8(end - 1))
	}
	if setup, _, ok := rtpFor(pi, tvb); ok {
		rt.AddGenerated(hfRTPSetup, d.UintValue(d.FtFrameNum, uint64(setup))).SetLink(setup)
	}
	if end > off {
		rt.AddBytes(hfRTPPay, tvb, off, end-off)
	}
	name := orDefault(rtpPayloadTypes[b1&0x7f], fmt.Sprintf("DynamicRTP-Type-%d", b1&0x7f))
	mark := ""
	if b1&0x80 != 0 {
		mark = ", Mark"
	}
	pi.SetInfo(fmt.Sprintf("PT=%s, SSRC=0x%X, Seq=%d, Time=%d%s", name, ssrc, seq, ts, mark))
	return tvb.Len()
}

func dissectRTCP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 8 || tvb.U8(0)>>6 != 2 {
		return 0
	}
	rt := tree.AddProtocol(protoRTCP, tvb, 0, -1)
	pi.SetProtocol("RTCP")
	var names []string
	for off := 0; tvb.Remaining(off) >= 4; {
		b0 := uint64(tvb.U8(off))
		pt := uint64(tvb.U8(off + 1))
		l := (int(tvb.U16(off+2)) + 1) * 4
		if off+l > tvb.Len() {
			l = tvb.Len() - off
		}
		pn := rt.AddText(tvb, off, l, "%s", orDefault(rtcpTypes[pt], "RTCP"))
		pn.AddBits(hfRTCPVer, tvb, off, 1, b0)
		pn.AddBits(hfRTCPPad, tvb, off, 1, b0)
		pn.AddBits(hfRTCPCount, tvb, off, 1, b0)
		pn.AddUint(hfRTCPPT, tvb, off+1, 1)
		pn.AddUint(hfRTCPLen, tvb, off+2, 2)
		names = append(names, orDefault(rtcpTypes[pt], fmt.Sprintf("PT %d", pt)))
		p := off + 4
		rc := int(b0 & 0x1f)
		switch pt {
		case 200, 201:
			pn.AddUint(hfRTCPSSRC, tvb, p, 4)
			p += 4
			if pt == 200 {
				pn.AddUint(hfRTCPNTPMSW, tvb, p, 4)
				pn.AddUint(hfRTCPNTPLSW, tvb, p+4, 4)
				pn.AddUint(hfRTCPRTPTS, tvb, p+8, 4)
				pn.AddUint(hfRTCPPkts, tvb, p+12, 4)
				pn.AddUint(hfRTCPOct, tvb, p+16, 4)
				p += 20
			}
			for i := 0; i < rc && tvb.Has(p, 24); i++ {
				bn := pn.AddText(tvb, p, 24, "Source %d", i+1)
				bn.AddUint(hfRTCPRBSSRC, tvb, p, 4)
				bn.AddUint(hfRTCPFrac, tvb, p+4, 1)
				lost := int64(tvb.U24(p + 5))
				if lost&0x800000 != 0 {
					lost -= 1 << 24
				}
				bn.AddValue(hfRTCPLost, tvb, p+5, 3, d.IntValue(d.FtInt32, lost))
				bn.AddUint(hfRTCPHigh, tvb, p+8, 4)
				bn.AddUint(hfRTCPJit, tvb, p+12, 4)
				p += 24
			}
		case 202:
			for i := 0; i < rc && p+4 <= off+l; i++ {
				pn.AddUint(hfRTCPSSRC, tvb, p, 4)
				p += 4
				for p+2 <= off+l && tvb.U8(p) != 0 {
					typ, tl := tvb.U8(p), int(tvb.U8(p+1))
					if typ == 1 {
						pn.AddString(hfRTCPCNAME, tvb, p+2, tl)
					} else {
						pn.AddString(hfRTCPSDES, tvb, p+2, tl)
					}
					p += 2 + tl
				}
				p = (p + 4) &^ 3
			}
		}
		off += l
	}
	pi.SetInfo(strings.Join(names, " "))
	return tvb.Len()
}
