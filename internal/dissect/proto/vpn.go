package proto

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

// ---------------- SSH ----------------

var (
	sshMsgs = map[uint64]string{1: "Disconnect", 2: "Ignore", 3: "Unimplemented", 4: "Debug", 5: "Service Request", 6: "Service Accept",
		20: "Key Exchange Init", 21: "New Keys", 30: "Diffie-Hellman Key Exchange Init", 31: "Diffie-Hellman Key Exchange Reply",
		50: "User Authentication Request", 51: "User Authentication Failure", 52: "User Authentication Success",
		80: "Global Request", 81: "Request Success", 82: "Request Failure", 90: "Channel Open", 91: "Channel Open Confirmation",
		92: "Channel Open Failure", 93: "Channel Window Adjust", 94: "Channel Data", 95: "Channel Extended Data", 96: "Channel EOF",
		97: "Channel Close", 98: "Channel Request", 99: "Channel Success", 100: "Channel Failure"}

	protoSSH      = d.RegisterProto("SSH Protocol", "SSH", "ssh")
	hfSSHProto    = protoSSH.Field("ssh.protocol", "Protocol", d.FtString)
	hfSSHDir      = protoSSH.Field("ssh.direction", "Direction", d.FtUint8, d.WithVS(map[uint64]string{0: "client-to-server", 1: "server-to-client"}))
	hfSSHPktLen   = protoSSH.Field("ssh.packet_length", "Packet Length", d.FtUint32)
	hfSSHPadLen   = protoSSH.Field("ssh.padding_length", "Padding Length", d.FtUint8)
	hfSSHMsg      = protoSSH.Field("ssh.message_code", "Message Code", d.FtUint8, d.WithVS(sshMsgs))
	hfSSHCookie   = protoSSH.Field("ssh.cookie", "Cookie", d.FtBytes)
	hfSSHKex      = protoSSH.Field("ssh.kex_algorithms", "kex_algorithms string", d.FtString)
	hfSSHHostKey  = protoSSH.Field("ssh.server_host_key_algorithms", "server_host_key_algorithms string", d.FtString)
	hfSSHEncC2S   = protoSSH.Field("ssh.encryption_algorithms_client_to_server", "encryption_algorithms_client_to_server string", d.FtString)
	hfSSHEncS2C   = protoSSH.Field("ssh.encryption_algorithms_server_to_client", "encryption_algorithms_server_to_client string", d.FtString)
	hfSSHMacC2S   = protoSSH.Field("ssh.mac_algorithms_client_to_server", "mac_algorithms_client_to_server string", d.FtString)
	hfSSHMacS2C   = protoSSH.Field("ssh.mac_algorithms_server_to_client", "mac_algorithms_server_to_client string", d.FtString)
	hfSSHCompC2S  = protoSSH.Field("ssh.compression_algorithms_client_to_server", "compression_algorithms_client_to_server string", d.FtString)
	hfSSHCompS2C  = protoSSH.Field("ssh.compression_algorithms_server_to_client", "compression_algorithms_server_to_client string", d.FtString)
	hfSSHLangC2S  = protoSSH.Field("ssh.languages_client_to_server", "languages_client_to_server string", d.FtString)
	hfSSHLangS2C  = protoSSH.Field("ssh.languages_server_to_client", "languages_server_to_client string", d.FtString)
	hfSSHFirstKex = protoSSH.Field("ssh.first_kex_packet_follows", "First KEX Packet Follows", d.FtUint8)
	hfSSHHassh    = protoSSH.Field("ssh.kex.hassh", "hassh", d.FtString)
	hfSSHHasshAlg = protoSSH.Field("ssh.kex.hassh_algorithms", "hasshAlgorithms", d.FtString)
	hfSSHHasshS   = protoSSH.Field("ssh.kex.hasshserver", "hasshServer", d.FtString)
	hfSSHHasshSA  = protoSSH.Field("ssh.kex.hasshserver_algorithms", "hasshServerAlgorithms", d.FtString)
	hfSSHEnc      = protoSSH.Field("ssh.encrypted_packet", "Encrypted Packet", d.FtBytes)
	hfSSHPayload  = protoSSH.Field("ssh.payload", "Payload", d.FtBytes)
	sshHandle     = d.RegisterHandle("ssh", d.NewHandle(protoSSH, dissectSSH))
)

type sshState struct {
	encFrom [2]uint32 // frame where NEWKEYS was seen per direction
}

func init() { TCPPortTable.Add(22, sshHandle) }

func dissectSSH(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	dir := 0
	if ti := CurrentTCP(pi); ti != nil && !ti.FromA {
		dir = 1
	}
	var st *sshState
	if pi.Conv != nil {
		st, _ = pi.Conv.Data(protoSSH).(*sshState)
		if st == nil {
			st = &sshState{}
			if !pi.Visited {
				pi.Conv.SetData(protoSSH, st)
			}
		}
	} else {
		st = &sshState{}
	}
	if string(tvb.Bytes(0, min(4, tvb.Len()))) == "SSH-" {
		st2 := tree.AddProtocol(protoSSH, tvb, 0, -1)
		pi.SetProtocol("SSHv2")
		line, next := tvb.LineEnd(0)
		_, banner := st2.AddString(hfSSHProto, tvb, 0, line)
		st2.AddGenerated(hfSSHDir, d.UintValue(d.FtUint8, uint64(dir)))
		_ = next
		pi.SetInfo(fmt.Sprintf("%s: Protocol (%s)", map[int]string{0: "Client", 1: "Server"}[dir], banner))
		if !strings.HasPrefix(banner, "SSH-2.0") && !strings.HasPrefix(banner, "SSH-1.99") {
			pi.SetProtocol("SSHv1")
		}
		return tvb.Len()
	}
	enc := st.encFrom[dir] != 0 && pi.Num > st.encFrom[dir]
	if enc {
		et := tree.AddProtocol(protoSSH, tvb, 0, -1)
		pi.SetProtocol("SSHv2")
		et.AddBytes(hfSSHEnc, tvb, 0, tvb.Len())
		pi.SetInfo(fmt.Sprintf("%s: Encrypted packet (len=%d)", map[int]string{0: "Client", 1: "Server"}[dir], tvb.Len()))
		return tvb.Len()
	}
	var infos []string
	sshTree := tree.AddProtocol(protoSSH, tvb, 0, -1)
	pi.SetProtocol("SSHv2")
	n := TCPDissectPDUs(tvb, pi, sshTree, 4, func(t *d.Tvb, off int) int {
		l := int(t.U32(off))
		if l > 35000 {
			return -1
		}
		return 4 + l
	}, func(t *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		pt := tree.AddText(t, 0, t.Len(), "SSH Version 2")
		pt.AddUint(hfSSHPktLen, t, 0, 4)
		_, pad := pt.AddUint(hfSSHPadLen, t, 4, 1)
		if t.Len() < 6 {
			return t.Len()
		}
		_, code := pt.AddUint(hfSSHMsg, t, 5, 1)
		infos = append(infos, map[int]string{0: "Client", 1: "Server"}[dir]+": "+orDefault(sshMsgs[code], fmt.Sprintf("Message %d", code)))
		switch code {
		case 20:
			dissectSSHKexInit(t, 6, pt, dir)
		case 21:
			if !pi.Visited {
				st.encFrom[dir] = pi.Num
			}
		default:
			if t.Len() > 6+int(pad) {
				pt.AddBytes(hfSSHPayload, t, 6, t.Len()-6-int(pad))
			}
		}
		return t.Len()
	})
	if len(infos) > 0 {
		pi.SetInfo(strings.Join(infos, ", "))
	}
	return n
}

func dissectSSHKexInit(t *d.Tvb, off int, pt *d.Node, dir int) {
	pt.AddBytes(hfSSHCookie, t, off, 16)
	off += 16
	fields := []*d.FieldDef{hfSSHKex, hfSSHHostKey, hfSSHEncC2S, hfSSHEncS2C, hfSSHMacC2S, hfSSHMacS2C, hfSSHCompC2S, hfSSHCompS2C, hfSSHLangC2S, hfSSHLangS2C}
	lists := make([]string, len(fields))
	for i, f := range fields {
		l := int(t.U32(off))
		ln := pt.AddText(t, off, 4+l, "")
		_, lists[i] = ln.AddString(f, t, off+4, l)
		ln.SetText("%s length: %d", strings.TrimSuffix(f.Name, " string"), l)
		off += 4 + l
	}
	pt.AddUint(hfSSHFirstKex, t, off, 1)
	// HASSH: kex;enc_c2s;mac_c2s;comp_c2s (server: kex;enc_s2c;mac_s2c;comp_s2c)
	var alg string
	var f1, f2 *d.FieldDef
	if dir == 0 {
		alg = strings.Join([]string{lists[0], lists[2], lists[4], lists[6]}, ";")
		f1, f2 = hfSSHHassh, hfSSHHasshAlg
	} else {
		alg = strings.Join([]string{lists[0], lists[3], lists[5], lists[7]}, ";")
		f1, f2 = hfSSHHasshS, hfSSHHasshSA
	}
	sum := md5.Sum([]byte(alg))
	pt.AddGenerated(f2, d.StringValue(alg))
	pt.AddGenerated(f1, d.StringValue(hex.EncodeToString(sum[:])))
}

// ---------------- WireGuard ----------------

var (
	wgTypes = map[uint64]string{1: "Handshake Initiation", 2: "Handshake Response", 3: "Cookie Reply", 4: "Transport Data"}

	protoWG     = d.RegisterProto("WireGuard Protocol", "WireGuard", "wg")
	hfWGType    = protoWG.Field("wg.type", "Message Type", d.FtUint8, d.WithVS(wgTypes))
	hfWGRes     = protoWG.Field("wg.reserved", "Reserved", d.FtBytes)
	hfWGSender  = protoWG.Field("wg.sender", "Sender", d.FtUint32, d.WithBase(d.BaseHex))
	hfWGRecv    = protoWG.Field("wg.receiver", "Receiver", d.FtUint32, d.WithBase(d.BaseHex))
	hfWGEph     = protoWG.Field("wg.ephemeral", "Ephemeral", d.FtBytes)
	hfWGStatic  = protoWG.Field("wg.static", "Encrypted Static", d.FtBytes)
	hfWGTS      = protoWG.Field("wg.timestamp", "Encrypted Timestamp", d.FtBytes)
	hfWGEmpty   = protoWG.Field("wg.encrypted_empty", "Encrypted Empty", d.FtBytes)
	hfWGMac1    = protoWG.Field("wg.mac1", "mac1", d.FtBytes)
	hfWGMac2    = protoWG.Field("wg.mac2", "mac2", d.FtBytes)
	hfWGNonce   = protoWG.Field("wg.nonce", "Nonce", d.FtBytes)
	hfWGCookie  = protoWG.Field("wg.encrypted_cookie", "Encrypted Cookie", d.FtBytes)
	hfWGCounter = protoWG.Field("wg.counter", "Counter", d.FtUint64)
	hfWGPacket  = protoWG.Field("wg.encrypted_packet", "Encrypted Packet", d.FtBytes)
	wgHandle    = d.RegisterHandle("wg", d.NewHandle(protoWG, dissectWG))
)

func init() {
	UDPPortTable.Add(51820, wgHandle)
	UDPHeur.Add("wg_udp", protoWG, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) bool {
		if !looksLikeWG(tvb, pi) {
			return false
		}
		dissectWG(tvb, pi, tree)
		return true
	})
}

func looksLikeWG(tvb *d.Tvb, pi *d.PacketInfo) bool {
	if tvb.Len() < 32 || tvb.U8(1) != 0 || tvb.U8(2) != 0 || tvb.U8(3) != 0 {
		return false
	}
	switch tvb.U8(0) {
	case 1:
		return tvb.Len() == 148
	case 2:
		return tvb.Len() == 92
	case 3:
		return tvb.Len() == 64
	case 4:
		if tvb.Len() < 32 || (tvb.Len()-16)%16 != 0 {
			return false
		}
		if pi.Conv == nil {
			return false
		}
		_, known := pi.Conv.Data(protoWG).(*bool)
		return known
	}
	return false
}

func dissectWG(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 32 {
		return 0
	}
	wt := tree.AddProtocol(protoWG, tvb, 0, -1)
	pi.SetProtocol("WireGuard")
	_, typ := wt.AddUint(hfWGType, tvb, 0, 1)
	wt.AddBytes(hfWGRes, tvb, 1, 3)
	info := wgTypes[typ]
	switch typ {
	case 1:
		_, s := wt.AddUint(hfWGSender, tvb, 4, 4)
		wt.AddBytes(hfWGEph, tvb, 8, 32)
		wt.AddBytes(hfWGStatic, tvb, 40, 48)
		wt.AddBytes(hfWGTS, tvb, 88, 28)
		wt.AddBytes(hfWGMac1, tvb, 116, 16)
		wt.AddBytes(hfWGMac2, tvb, 132, 16)
		info += fmt.Sprintf(", sender=0x%08X", s)
		if pi.Conv != nil && !pi.Visited {
			t := true
			pi.Conv.SetData(protoWG, &t)
		}
	case 2:
		_, s := wt.AddUint(hfWGSender, tvb, 4, 4)
		_, r := wt.AddUint(hfWGRecv, tvb, 8, 4)
		wt.AddBytes(hfWGEph, tvb, 12, 32)
		wt.AddBytes(hfWGEmpty, tvb, 44, 16)
		wt.AddBytes(hfWGMac1, tvb, 60, 16)
		wt.AddBytes(hfWGMac2, tvb, 76, 16)
		info += fmt.Sprintf(", sender=0x%08X, receiver=0x%08X", s, r)
	case 3:
		_, r := wt.AddUint(hfWGRecv, tvb, 4, 4)
		wt.AddBytes(hfWGNonce, tvb, 8, 24)
		wt.AddBytes(hfWGCookie, tvb, 32, 32)
		info += fmt.Sprintf(", receiver=0x%08X", r)
	case 4:
		_, r := wt.AddUint(hfWGRecv, tvb, 4, 4)
		_, c := wt.AddUintLE(hfWGCounter, tvb, 8, 8)
		wt.AddBytes(hfWGPacket, tvb, 16, tvb.Len()-16)
		info += fmt.Sprintf(", receiver=0x%08X, counter=%d, datalen=%d", r, c, tvb.Len()-32)
	default:
		return 0
	}
	pi.SetInfo(info)
	return tvb.Len()
}

// ---------------- OpenVPN ----------------

var (
	ovpnOps = map[uint64]string{1: "P_CONTROL_HARD_RESET_CLIENT_V1", 2: "P_CONTROL_HARD_RESET_SERVER_V1", 3: "P_CONTROL_SOFT_RESET_V1",
		4: "P_CONTROL_V1", 5: "P_ACK_V1", 6: "P_DATA_V1", 7: "P_CONTROL_HARD_RESET_CLIENT_V2", 8: "P_CONTROL_HARD_RESET_SERVER_V2",
		9: "P_DATA_V2", 10: "P_CONTROL_HARD_RESET_CLIENT_V3", 11: "P_CONTROL_WKC_V1"}

	protoOVPN    = d.RegisterProto("OpenVPN Protocol", "OpenVPN", "openvpn")
	hfOVPNLen    = protoOVPN.Field("openvpn.plen", "Packet Length", d.FtUint16)
	hfOVPNOp     = protoOVPN.Field("openvpn.opcode", "Opcode", d.FtUint8, d.WithMask(0xf8), d.WithVS(ovpnOps))
	hfOVPNKey    = protoOVPN.Field("openvpn.keyid", "Key ID", d.FtUint8, d.WithMask(0x07))
	hfOVPNSess   = protoOVPN.Field("openvpn.sessionid", "Session ID", d.FtUint64)
	hfOVPNAcks   = protoOVPN.Field("openvpn.mpid_arrayno", "Message-Packet-ID Array Length", d.FtUint8)
	hfOVPNAck    = protoOVPN.Field("openvpn.mpid_array", "Message Packet-ID", d.FtUint32)
	hfOVPNRemote = protoOVPN.Field("openvpn.rsessionid", "Remote Session ID", d.FtUint64)
	hfOVPNPID    = protoOVPN.Field("openvpn.mpid", "Message Packet-ID", d.FtUint32)
	hfOVPNPeer   = protoOVPN.Field("openvpn.peerid", "Peer-ID", d.FtUint24, d.WithBase(d.BaseHex))
	hfOVPNData   = protoOVPN.Field("openvpn.data", "Data", d.FtBytes)
	ovpnHandle   = d.RegisterHandle("openvpn", d.NewHandle(protoOVPN, dissectOpenVPNUDP))
	ovpnTCP      = d.RegisterHandle("openvpn-tcp", d.NewHandle(protoOVPN, dissectOpenVPNTCP))
)

func init() {
	UDPPortTable.Add(1194, ovpnHandle)
	TCPPortTable.Add(1194, ovpnTCP)
}

func dissectOpenVPNUDP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 2 {
		return 0
	}
	op := uint64(tvb.U8(0) >> 3)
	if op < 1 || op > 11 {
		return 0
	}
	ot := tree.AddProtocol(protoOVPN, tvb, 0, -1)
	pi.SetProtocol("OpenVPN")
	pi.SetInfo(openvpnMsg(tvb, 0, ot))
	return tvb.Len()
}

func dissectOpenVPNTCP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	ot := tree.AddProtocol(protoOVPN, tvb, 0, -1)
	pi.SetProtocol("OpenVPN")
	var infos []string
	n := TCPDissectPDUs(tvb, pi, ot, 2, func(t *d.Tvb, off int) int { return 2 + int(t.U16(off)) },
		func(t *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
			tree.AddUint(hfOVPNLen, t, 0, 2)
			infos = append(infos, openvpnMsg(t, 2, tree))
			return t.Len()
		})
	pi.SetInfo(strings.Join(infos, ", "))
	return n
}

func openvpnMsg(t *d.Tvb, off int, tree *d.Node) string {
	b := uint64(t.U8(off))
	op := b >> 3
	tree.AddBits(hfOVPNOp, t, off, 1, b)
	tree.AddBits(hfOVPNKey, t, off, 1, b)
	name := orDefault(ovpnOps[op], "Unknown")
	switch op {
	case 6:
		t2 := t.Remaining(off + 1)
		if t2 > 0 {
			tree.AddBytes(hfOVPNData, t, off+1, t2)
		}
	case 9:
		tree.AddUint(hfOVPNPeer, t, off+1, 3)
		if t.Remaining(off+4) > 0 {
			tree.AddBytes(hfOVPNData, t, off+4, t.Remaining(off+4))
		}
	default:
		p := off + 1
		tree.AddUint(hfOVPNSess, t, p, 8)
		p += 8
		_, n := tree.AddUint(hfOVPNAcks, t, p, 1)
		p++
		for i := 0; i < int(n); i++ {
			tree.AddUint(hfOVPNAck, t, p, 4)
			p += 4
		}
		if n > 0 {
			tree.AddUint(hfOVPNRemote, t, p, 8)
			p += 8
		}
		if op != 5 {
			tree.AddUint(hfOVPNPID, t, p, 4)
			p += 4
		}
		if t.Remaining(p) > 0 {
			tree.AddBytes(hfOVPNData, t, p, t.Remaining(p))
		}
	}
	return "MessageType: " + name
}

// ---------------- IKE / ISAKMP ----------------

var (
	ikeExch = map[uint64]string{0: "NONE", 1: "Base", 2: "Identity Protection (Main Mode)", 3: "Authentication Only", 4: "Aggressive",
		5: "Informational", 32: "Quick Mode", 33: "New Group Mode", 34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA",
		37: "INFORMATIONAL", 38: "IKE_SESSION_RESUME", 39: "GSA_AUTH", 40: "GSA_REGISTRATION", 41: "GSA_REKEY"}
	ikePayloads = map[uint64]string{0: "NONE", 1: "Security Association (v1)", 2: "Proposal (v1)", 3: "Transform (v1)", 4: "Key Exchange (v1)",
		5: "Identification (v1)", 6: "Certificate (v1)", 7: "Certificate Request (v1)", 8: "Hash (v1)", 9: "Signature (v1)", 10: "Nonce (v1)",
		11: "Notification (v1)", 12: "Delete (v1)", 13: "Vendor ID (v1)", 33: "Security Association", 34: "Key Exchange",
		35: "Identification - Initiator", 36: "Identification - Responder", 37: "Certificate", 38: "Certificate Request",
		39: "Authentication", 40: "Nonce", 41: "Notify", 42: "Delete", 43: "Vendor ID", 44: "Traffic Selector - Initiator",
		45: "Traffic Selector - Responder", 46: "Encrypted and Authenticated", 47: "Configuration", 48: "Extensible Authentication", 53: "Encrypted Fragment"}

	protoIKE   = d.RegisterProto("Internet Security Association and Key Management Protocol", "ISAKMP", "isakmp")
	hfIKEISPI  = protoIKE.Field("isakmp.ispi", "Initiator SPI", d.FtBytes)
	hfIKERSPI  = protoIKE.Field("isakmp.rspi", "Responder SPI", d.FtBytes)
	hfIKENext  = protoIKE.Field("isakmp.nextpayload", "Next payload", d.FtUint8, d.WithVS(ikePayloads))
	hfIKEMaj   = protoIKE.Field("isakmp.version", "Version", d.FtUint8, d.WithBase(d.BaseHex))
	hfIKEExch  = protoIKE.Field("isakmp.exchangetype", "Exchange type", d.FtUint8, d.WithVS(ikeExch))
	hfIKEFlags = protoIKE.Field("isakmp.flags", "Flags", d.FtUint8, d.WithBase(d.BaseHex))
	hfIKEMsgID = protoIKE.Field("isakmp.messageid", "Message ID", d.FtUint32, d.WithBase(d.BaseHex))
	hfIKELen   = protoIKE.Field("isakmp.length", "Length", d.FtUint32)
	hfIKEPType = protoIKE.Field("isakmp.payload.type", "Payload type", d.FtUint8, d.WithVS(ikePayloads))
	hfIKEPLen  = protoIKE.Field("isakmp.payload.length", "Payload length", d.FtUint16)
	hfIKEPData = protoIKE.Field("isakmp.payload.data", "Payload data", d.FtBytes)
	ikeHandle  = d.RegisterHandle("isakmp", d.NewHandle(protoIKE, dissectIKE))
	protoESP   = d.RegisterProto("Encapsulating Security Payload", "ESP", "esp")
	hfESPSPI   = protoESP.Field("esp.spi", "SPI", d.FtUint32, d.WithBase(d.BaseHex))
	hfESPSeq   = protoESP.Field("esp.sequence", "Sequence Number", d.FtUint32)
	hfESPData  = protoESP.Field("esp.encrypted_data", "Encrypted Data", d.FtBytes)
	espHandle  = d.RegisterHandle("esp", d.NewHandle(protoESP, dissectESP))
	protoAH    = d.RegisterProto("Authentication Header", "AH", "ah")
	hfAHNext   = protoAH.Field("ah.next_header", "Next Header", d.FtUint8, d.WithVS(IPProtos))
	hfAHLen    = protoAH.Field("ah.length", "Length", d.FtUint8)
	hfAHSPI    = protoAH.Field("ah.spi", "AH SPI", d.FtUint32, d.WithBase(d.BaseHex))
	hfAHSeq    = protoAH.Field("ah.sequence", "AH Sequence", d.FtUint32)
	hfAHICV    = protoAH.Field("ah.icv", "AH ICV", d.FtBytes)
)

func init() {
	UDPPortTable.Add(500, ikeHandle)
	UDPPortTable.Add(4500, d.NewHandle(protoIKE, dissectIKENatT))
	IPProtoTable.Add(50, espHandle)
	IPProtoTable.Add(51, d.NewHandle(protoAH, dissectAH))
}

func dissectIKENatT(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() >= 4 && tvb.U32(0) == 0 {
		return dissectIKE(tvb.Sub(4, -1), pi, tree)
	}
	if tvb.Len() == 1 && tvb.U8(0) == 0xff {
		pi.SetProtocol("UDPENCAP")
		pi.SetInfo("NAT-keepalive")
		return 1
	}
	return dissectESP(tvb, pi, tree)
}

func dissectIKE(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 28 {
		return 0
	}
	it := tree.AddProtocol(protoIKE, tvb, 0, -1)
	pi.SetProtocol("ISAKMP")
	it.AddBytes(hfIKEISPI, tvb, 0, 8)
	it.AddBytes(hfIKERSPI, tvb, 8, 8)
	_, next := it.AddUint(hfIKENext, tvb, 16, 1)
	ver := tvb.U8(17)
	it.AddUint(hfIKEMaj, tvb, 17, 1)
	_, ex := it.AddUint(hfIKEExch, tvb, 18, 1)
	it.AddUint(hfIKEFlags, tvb, 19, 1)
	it.AddUint(hfIKEMsgID, tvb, 20, 4)
	_, total := it.AddUint(hfIKELen, tvb, 24, 4)
	end := min(int(total), tvb.Len())
	var names []string
	for off := 28; off+4 <= end && next != 0; {
		pl := int(tvb.U16(off + 2))
		if pl < 4 || off+pl > tvb.Len() {
			break
		}
		pn := it.AddText(tvb, off, pl, "Payload: %s (%d)", orDefault(ikePayloads[next], "Unknown"), next)
		pn.AddValue(hfIKEPType, nil, 0, 0, d.UintValue(d.FtUint8, next))
		pn.AddUint(hfIKEPLen, tvb, off+2, 2)
		if pl > 4 {
			pn.AddBytes(hfIKEPData, tvb, off+4, pl-4)
		}
		names = append(names, ikePayloads[next])
		next = uint64(tvb.U8(off))
		off += pl
	}
	flagsB := tvb.U8(19)
	info := orDefault(ikeExch[ex], "Unknown")
	if ver>>4 == 2 {
		role := "Responder"
		if flagsB&0x08 != 0 {
			role = "Initiator"
		}
		kind := "Request"
		if flagsB&0x20 != 0 {
			kind = "Response"
		}
		info = fmt.Sprintf("%s MID=%02x %s %s", info, tvb.U32(20), role, kind)
	}
	pi.SetInfo(info)
	return tvb.Len()
}

func dissectESP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 8 {
		return 0
	}
	et := tree.AddProtocol(protoESP, tvb, 0, -1)
	pi.SetProtocol("ESP")
	_, spi := et.AddUint(hfESPSPI, tvb, 0, 4)
	_, seq := et.AddUint(hfESPSeq, tvb, 4, 4)
	et.AddBytes(hfESPData, tvb, 8, tvb.Len()-8)
	pi.SetInfo(fmt.Sprintf("ESP (SPI=0x%08x)", spi))
	_ = seq
	return tvb.Len()
}

func dissectAH(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 12 {
		return 0
	}
	at := tree.AddProtocol(protoAH, tvb, 0, -1)
	pi.SetProtocol("AH")
	_, nxt := at.AddUint(hfAHNext, tvb, 0, 1)
	_, l := at.AddUint(hfAHLen, tvb, 1, 1)
	_, spi := at.AddUint(hfAHSPI, tvb, 4, 4)
	_, seq := at.AddUint(hfAHSeq, tvb, 8, 4)
	hl := int(l+2) * 4
	if hl > 12 && tvb.Len() >= hl {
		at.AddBytes(hfAHICV, tvb, 12, hl-12)
	}
	pi.SetInfo(fmt.Sprintf("AH (SPI=0x%08x)", spi))
	_ = seq
	if tvb.Len() > hl {
		if _, ok := IPProtoTable.Try(nxt, tvb.Sub(hl, -1), pi, tree); ok {
			return tvb.Len()
		}
	}
	return tvb.Len()
}

// ---------------- L2TP ----------------

var (
	l2tpTypes = map[uint64]string{1: "Start_Control_Connection_Request", 2: "Start_Control_Connection_Reply", 3: "Start_Control_Connection_Connected",
		4: "Stop_Control_Connection_Notification", 6: "Hello", 7: "Outgoing_Call_Request", 8: "Outgoing_Call_Reply", 9: "Outgoing_Call_Connected",
		10: "Incoming_Call_Request", 11: "Incoming_Call_Reply", 12: "Incoming_Call_Connected", 14: "Call_Disconnect_Notify", 15: "WAN_Error_Notify",
		16: "Set_Link_Info", 20: "Zero_Length_Body"}

	protoL2TP  = d.RegisterProto("Layer 2 Tunneling Protocol", "L2TP", "l2tp")
	hfL2TPType = protoL2TP.Field("l2tp.type", "Type", d.FtUint16, d.WithMask(0x8000), d.WithParentBits(16), d.WithVS(map[uint64]string{0: "Data Message", 1: "Control Message"}))
	hfL2TPVer  = protoL2TP.Field("l2tp.version", "Version", d.FtUint16, d.WithMask(0x000f), d.WithParentBits(16))
	hfL2TPLen  = protoL2TP.Field("l2tp.length", "Length", d.FtUint16)
	hfL2TPTun  = protoL2TP.Field("l2tp.tunnel", "Tunnel ID", d.FtUint16)
	hfL2TPSess = protoL2TP.Field("l2tp.session", "Session ID", d.FtUint16)
	hfL2TPNs   = protoL2TP.Field("l2tp.Ns", "Ns", d.FtUint16)
	hfL2TPNr   = protoL2TP.Field("l2tp.Nr", "Nr", d.FtUint16)
	hfL2TPMsg  = protoL2TP.Field("l2tp.avp.message_type", "Message Type", d.FtUint16, d.WithVS(l2tpTypes))
	hfL2TPPay  = protoL2TP.Field("l2tp.payload", "Payload", d.FtBytes)
	l2tpHandle = d.RegisterHandle("l2tp", d.NewHandle(protoL2TP, dissectL2TP))
)

func init() { UDPPortTable.Add(1701, l2tpHandle) }

func dissectL2TP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 6 {
		return 0
	}
	flags := tvb.U16(0)
	if flags&0x000f != 2 {
		return 0
	}
	lt := tree.AddProtocol(protoL2TP, tvb, 0, -1)
	pi.SetProtocol("L2TP")
	lt.AddBits(hfL2TPType, tvb, 0, 2, uint64(flags))
	lt.AddBits(hfL2TPVer, tvb, 0, 2, uint64(flags))
	off := 2
	if flags&0x4000 != 0 {
		lt.AddUint(hfL2TPLen, tvb, off, 2)
		off += 2
	}
	lt.AddUint(hfL2TPTun, tvb, off, 2)
	lt.AddUint(hfL2TPSess, tvb, off+2, 2)
	off += 4
	if flags&0x0800 != 0 {
		lt.AddUint(hfL2TPNs, tvb, off, 2)
		lt.AddUint(hfL2TPNr, tvb, off+2, 2)
		off += 4
	}
	if flags&0x0200 != 0 {
		off += 2 + int(tvb.U16(off))
	}
	if flags&0x8000 != 0 {
		info := "Control Message"
		for p := off; p+6 <= tvb.Len(); {
			l := int(tvb.U16(p) & 0x03ff)
			if l < 6 || p+l > tvb.Len() {
				break
			}
			if tvb.U16(p+2) == 0 && tvb.U16(p+4) == 0 && l >= 8 {
				_, mt := lt.AddUint(hfL2TPMsg, tvb, p+6, 2)
				info = "Control Message - " + l2tpTypes[mt]
			}
			p += l
		}
		if off >= tvb.Len() {
			info = "Control Message - ZLB"
		}
		pi.SetInfo(info)
	} else {
		pi.SetInfo("Data Message")
		if off < tvb.Len() {
			lt.AddBytes(hfL2TPPay, tvb, off, tvb.Len()-off)
		}
	}
	return tvb.Len()
}

// ---------------- STUN ----------------

var (
	stunTypes = map[uint64]string{0x0001: "Binding Request", 0x0101: "Binding Success Response", 0x0111: "Binding Error Response",
		0x0003: "Allocate Request", 0x0103: "Allocate Success Response", 0x0113: "Allocate Error Response", 0x0004: "Refresh Request",
		0x0104: "Refresh Success Response", 0x0006: "Send Indication", 0x0016: "Send Indication", 0x0017: "Data Indication",
		0x0008: "CreatePermission Request", 0x0108: "CreatePermission Success Response", 0x0009: "ChannelBind Request",
		0x0109: "ChannelBind Success Response"}
	stunAttrs = map[uint64]string{0x0001: "MAPPED-ADDRESS", 0x0006: "USERNAME", 0x0008: "MESSAGE-INTEGRITY", 0x0009: "ERROR-CODE",
		0x000a: "UNKNOWN-ATTRIBUTES", 0x000c: "CHANNEL-NUMBER", 0x000d: "LIFETIME", 0x0012: "XOR-PEER-ADDRESS", 0x0013: "DATA",
		0x0014: "REALM", 0x0015: "NONCE", 0x0016: "XOR-RELAYED-ADDRESS", 0x0019: "REQUESTED-TRANSPORT", 0x0020: "XOR-MAPPED-ADDRESS",
		0x0024: "PRIORITY", 0x0025: "USE-CANDIDATE", 0x8022: "SOFTWARE", 0x8028: "FINGERPRINT", 0x8029: "ICE-CONTROLLED", 0x802a: "ICE-CONTROLLING",
		0x802b: "RESPONSE-ORIGIN", 0x802c: "OTHER-ADDRESS"}

	protoSTUN   = d.RegisterProto("Session Traversal Utilities for NAT", "STUN", "stun")
	hfSTUNType  = protoSTUN.Field("stun.type", "Message Type", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(stunTypes))
	hfSTUNLen   = protoSTUN.Field("stun.length", "Message Length", d.FtUint16)
	hfSTUNMagic = protoSTUN.Field("stun.cookie", "Message Cookie", d.FtBytes)
	hfSTUNID    = protoSTUN.Field("stun.id", "Message Transaction ID", d.FtBytes)
	hfSTUNAttr  = protoSTUN.Field("stun.attribute", "Attribute", d.FtNone)
	hfSTUNAType = protoSTUN.Field("stun.att.type", "Attribute Type", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(stunAttrs))
	hfSTUNALen  = protoSTUN.Field("stun.att.length", "Attribute Length", d.FtUint16)
	hfSTUNIPv4  = protoSTUN.Field("stun.att.ipv4", "IP", d.FtIPv4)
	hfSTUNPort  = protoSTUN.Field("stun.att.port", "Port", d.FtUint16)
	hfSTUNSoft  = protoSTUN.Field("stun.att.software", "Software", d.FtString)
	hfSTUNUser  = protoSTUN.Field("stun.att.username", "Username", d.FtString)
	hfSTUNValue = protoSTUN.Field("stun.value", "Value", d.FtBytes)
	stunHandle  = d.RegisterHandle("stun", d.NewHandle(protoSTUN, dissectSTUN))
)

func init() {
	UDPPortTable.Add(3478, stunHandle)
	UDPPortTable.Add(5349, stunHandle)
	TCPPortTable.Add(3478, stunHandle)
	UDPHeur.Add("stun_udp", protoSTUN, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) bool {
		if tvb.Len() < 20 || tvb.U8(0)&0xc0 != 0 || tvb.U32(4) != 0x2112a442 || int(tvb.U16(2))+20 != tvb.Len() {
			return false
		}
		dissectSTUN(tvb, pi, tree)
		return true
	})
}

func dissectSTUN(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 20 || tvb.U32(4) != 0x2112a442 {
		return 0
	}
	st := tree.AddProtocol(protoSTUN, tvb, 0, -1)
	pi.SetProtocol("STUN")
	_, mt := st.AddUint(hfSTUNType, tvb, 0, 2)
	_, ml := st.AddUint(hfSTUNLen, tvb, 2, 2)
	st.AddBytes(hfSTUNMagic, tvb, 4, 4)
	st.AddBytes(hfSTUNID, tvb, 8, 12)
	info := orDefault(stunTypes[mt], fmt.Sprintf("0x%04x", mt))
	end := min(20+int(ml), tvb.Len())
	for off := 20; off+4 <= end; {
		at := uint64(tvb.U16(off))
		al := int(tvb.U16(off + 2))
		an := st.AddText(tvb, off, 4+al, "Attribute: %s", orDefault(stunAttrs[at], fmt.Sprintf("0x%04x", at)))
		an.AddUint(hfSTUNAType, tvb, off, 2)
		an.AddUint(hfSTUNALen, tvb, off+2, 2)
		v := off + 4
		switch at {
		case 0x0001, 0x0020, 0x0012, 0x0016, 0x802b, 0x802c:
			if al >= 8 && tvb.U8(v+1) == 1 {
				port := tvb.U16(v + 2)
				ip := tvb.U32(v + 4)
				if at == 0x0020 || at == 0x0012 || at == 0x0016 {
					port ^= 0x2112
					ip ^= 0x2112a442
				}
				an.AddGenerated(hfSTUNPort, d.UintValue(d.FtUint16, uint64(port)))
				an.AddGenerated(hfSTUNIPv4, d.UintValue(d.FtIPv4, uint64(ip)))
				an.AppendText(": %d.%d.%d.%d:%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), port)
				if at == 0x0020 {
					info += fmt.Sprintf(" XOR-MAPPED-ADDRESS: %d.%d.%d.%d:%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), port)
				}
			}
		case 0x8022:
			an.AddString(hfSTUNSoft, tvb, v, al)
		case 0x0006:
			_, u := an.AddString(hfSTUNUser, tvb, v, al)
			info += " user: " + u
		default:
			if al > 0 {
				an.AddBytes(hfSTUNValue, tvb, v, al)
			}
		}
		off += 4 + (al+3)&^3
	}
	pi.SetInfo(info)
	return tvb.Len()
}
