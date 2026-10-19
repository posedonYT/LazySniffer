package proto

import (
	"fmt"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	protoDTLS     = d.RegisterProto("Datagram Transport Layer Security", "DTLS", "dtls")
	hfDTLSRecord  = protoDTLS.Field("dtls.record", "Record Layer", d.FtNone)
	hfDTLSType    = protoDTLS.Field("dtls.record.content_type", "Content Type", d.FtUint8, d.WithVS(tlsContentTypes))
	hfDTLSVersion = protoDTLS.Field("dtls.record.version", "Version", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(tlsVersionVS()))
	hfDTLSEpoch   = protoDTLS.Field("dtls.record.epoch", "Epoch", d.FtUint16)
	hfDTLSSeq     = protoDTLS.Field("dtls.record.sequence_number", "Sequence Number", d.FtUint48)
	hfDTLSLength  = protoDTLS.Field("dtls.record.length", "Length", d.FtUint16)
	hfDTLSMsgSeq  = protoDTLS.Field("dtls.handshake.message_seq", "Message Sequence", d.FtUint16)
	hfDTLSFragOff = protoDTLS.Field("dtls.handshake.fragment_offset", "Fragment Offset", d.FtUint24)
	hfDTLSFragLen = protoDTLS.Field("dtls.handshake.fragment_length", "Fragment Length", d.FtUint24)
	hfDTLSAppData = protoDTLS.Field("dtls.app_data", "Encrypted Application Data", d.FtBytes)
	hfDTLSEncHS   = protoDTLS.Field("dtls.handshake.encrypted", "Encrypted Handshake Message", d.FtBytes)
	dtlsHandle    = d.RegisterHandle("dtls", d.NewHandle(protoDTLS, dissectDTLS))
)

func init() {
	UDPHeur.Add("dtls_udp", protoDTLS, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) bool {
		if !looksLikeDTLS(tvb) {
			return false
		}
		dissectDTLS(tvb, pi, tree)
		return true
	})
	UDPPortTable.Add(4433, dtlsHandle)
	UDPPortTable.Add(5684, dtlsHandle) // CoAP over DTLS
}

func looksLikeDTLS(tvb *d.Tvb) bool {
	if tvb.Len() < 13 {
		return false
	}
	t, v := tvb.U8(0), tvb.U16(1)
	l := int(tvb.U16(11))
	return t >= 20 && t <= 26 && (v == 0xfeff || v == 0xfefd || v == 0xfefc || v == 0x0100) && 13+l <= tvb.Len()
}

func dissectDTLS(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 13 {
		return 0
	}
	sess, dir := tlsSessionOf(pi)
	dt := tree.AddProtocol(protoDTLS, tvb, 0, -1)
	var infos []string
	for off := 0; tvb.Remaining(off) >= 13; {
		typ := uint64(tvb.U8(off))
		ver := tvb.U16(off + 1)
		epoch := tvb.U16(off + 3)
		l := int(tvb.U16(off + 11))
		pi.SetProtocol(versionShort(ver))
		rt := dt.AddValue(hfDTLSRecord, tvb, off, min(13+l, tvb.Remaining(off)), d.Value{})
		rt.AddUint(hfDTLSType, tvb, off, 1)
		rt.AddUint(hfDTLSVersion, tvb, off+1, 2)
		rt.AddUint(hfDTLSEpoch, tvb, off+3, 2)
		rt.AddUint(hfDTLSSeq, tvb, off+5, 6)
		rt.AddUint(hfDTLSLength, tvb, off+11, 2)
		body := tvb.Sub(off+13, min(l, tvb.Remaining(off+13)))
		label := versionShort(ver) + " Record Layer: "
		switch typ {
		case 22:
			if epoch > 0 {
				rt.AddBytes(hfDTLSEncHS, body, 0, body.Len())
				label += "Handshake Protocol: Encrypted Handshake Message"
				infos = append(infos, "Encrypted Handshake Message")
				break
			}
			var names []string
			for p := 0; body.Remaining(p) >= 12; {
				fl := int(body.U24(p + 9))
				msg := body.Sub(p, min(12+fl, body.Remaining(p)))
				name := dissectHandshakeMsg(msg, pi, rt, sess, dir, "d", &infos)
				// The DTLS-specific header fields follow the common ones.
				hn := rt.Last
				if hn != nil {
					hn.AddUint(hfDTLSMsgSeq, body, p+4, 2)
					hn.AddUint(hfDTLSFragOff, body, p+6, 3)
					hn.AddUint(hfDTLSFragLen, body, p+9, 3)
				}
				names = append(names, name)
				p += 12 + fl
			}
			label += "Handshake Protocol: " + strings.Join(names, ", ")
		case 20:
			rt.AddValue(hfTLSCCS, body, 0, body.Len(), d.Value{})
			label += "Change Cipher Spec Protocol: Change Cipher Spec"
			infos = append(infos, "Change Cipher Spec")
		case 21:
			if epoch > 0 {
				rt.AddBytes(hfDTLSAppData, body, 0, body.Len())
				label += "Encrypted Alert"
				infos = append(infos, "Encrypted Alert")
				break
			}
			an := rt.AddValue(hfTLSAlert, body, 0, 2, d.Value{})
			_, lv := an.AddUint(hfTLSAlertLevel, body, 0, 1)
			_, ds := an.AddUint(hfTLSAlertDesc, body, 1, 1)
			s := fmt.Sprintf("Alert (Level: %s, Description: %s)", tlsAlertLevels[lv], tlsAlertDescs[ds])
			label += s
			infos = append(infos, s)
		case 23:
			rt.AddBytes(hfDTLSAppData, body, 0, body.Len())
			label += "Application Data Protocol: Application Data"
			infos = append(infos, "Application Data")
		default:
			label += "Unknown"
		}
		rt.SetText("%s", label)
		off += 13 + l
	}
	pi.SetInfo(strings.Join(infos, ", "))
	return tvb.Len()
}
