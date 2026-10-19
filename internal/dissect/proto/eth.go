package proto

import (
	d "github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/pcapio"
)

// EtherTypes names Ethernet payload types.
var EtherTypes = map[uint64]string{
	0x0800: "IPv4", 0x0806: "ARP", 0x0842: "Wake on LAN", 0x22f3: "TRILL",
	0x6558: "Transparent Ethernet bridging", 0x8035: "RARP", 0x809b: "AppleTalk",
	0x80f3: "AARP", 0x8100: "802.1Q Virtual LAN", 0x8137: "Netware IPX/SPX",
	0x86dd: "IPv6", 0x8808: "MAC Control", 0x8809: "Slow Protocols",
	0x8847: "MPLS label switched packet", 0x8848: "MPLS multicast label switched packet",
	0x8863: "PPPoE Discovery", 0x8864: "PPPoE Session", 0x886d: "Intel ANS probe",
	0x888e: "802.1X Authentication", 0x8892: "PROFINET", 0x889a: "HyperSCSI",
	0x88a2: "ATA over Ethernet", 0x88a4: "EtherCAT frame", 0x88a8: "802.1ad Provider Bridge (Q-in-Q)",
	0x88b8: "GOOSE", 0x88cc: "802.1 Link Layer Discovery Protocol (LLDP)",
	0x88e1: "HomePlug AV", 0x88e3: "Media Redundancy Protocol (IEC62439-2)",
	0x88e5: "802.1AE (MACsec)", 0x88e7: "802.1ah Provider Backbone Bridge",
	0x88f7: "PTPv2 over Ethernet (IEEE1588)", 0x8902: "802.1ag Connectivity Fault Management (CFM) Protocol",
	0x8906: "Fibre Channel over Ethernet (FCoE)", 0x8914: "FCoE Initialization Protocol",
	0x893a: "IEEE 1905.1a", 0x9000: "Configuration Test Protocol (loopback)",
	0x9100: "VLAN-tagged frame (Q-in-Q)",
}

var (
	protoEth = d.RegisterProto("Ethernet", "Ethernet", "eth")

	tfsLG = &d.TrueFalse{True: "Locally administered address (this is NOT the factory default)", False: "Globally unique address (factory default)"}
	tfsIG = &d.TrueFalse{True: "Group address (multicast/broadcast)", False: "Individual address (unicast)"}

	hfEthDst      = protoEth.Field("eth.dst", "Destination", d.FtEther)
	hfEthDstRes   = protoEth.Field("eth.dst_resolved", "Destination (resolved)", d.FtString)
	hfEthDstOUI   = protoEth.Field("eth.dst.oui", "Destination OUI", d.FtUint24, d.WithBase(d.BaseHex))
	hfEthDstLG    = protoEth.Field("eth.dst.lg", "LG bit", d.FtBool, d.WithMask(0x020000), d.WithParentBits(24), d.WithTFS(tfsLG))
	hfEthDstIG    = protoEth.Field("eth.dst.ig", "IG bit", d.FtBool, d.WithMask(0x010000), d.WithParentBits(24), d.WithTFS(tfsIG))
	hfEthSrc      = protoEth.Field("eth.src", "Source", d.FtEther)
	hfEthSrcRes   = protoEth.Field("eth.src_resolved", "Source (resolved)", d.FtString)
	hfEthSrcOUI   = protoEth.Field("eth.src.oui", "Source OUI", d.FtUint24, d.WithBase(d.BaseHex))
	hfEthSrcLG    = protoEth.Field("eth.src.lg", "LG bit", d.FtBool, d.WithMask(0x020000), d.WithParentBits(24), d.WithTFS(tfsLG))
	hfEthSrcIG    = protoEth.Field("eth.src.ig", "IG bit", d.FtBool, d.WithMask(0x010000), d.WithParentBits(24), d.WithTFS(tfsIG))
	hfEthAddr     = protoEth.Field("eth.addr", "Address", d.FtEther)
	hfEthAddrRes  = protoEth.Field("eth.addr_resolved", "Address (resolved)", d.FtString)
	hfEthLG       = protoEth.Field("eth.lg", "LG bit", d.FtBool, d.WithMask(0x020000), d.WithParentBits(24), d.WithTFS(tfsLG))
	hfEthIG       = protoEth.Field("eth.ig", "IG bit", d.FtBool, d.WithMask(0x010000), d.WithParentBits(24), d.WithTFS(tfsIG))
	hfEthType     = protoEth.Field("eth.type", "Type", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(EtherTypes))
	hfEthLen      = protoEth.Field("eth.len", "Length", d.FtUint16)
	hfEthPadding  = protoEth.Field("eth.padding", "Padding", d.FtBytes)
	hfEthTrailer  = protoEth.Field("eth.trailer", "Trailer", d.FtBytes)
	hfEthFCS      = protoEth.Field("eth.fcs", "Frame check sequence", d.FtUint32, d.WithBase(d.BaseHex))
	eiEthInvalidL = protoEth.Expert("eth.invalid_lentype", d.GroupProtocol, d.SevWarn, "Invalid length/type")

	// EtherTypeTable dispatches on the Ethernet type.
	EtherTypeTable = d.Table("ethertype")
	ethHandle      = d.RegisterHandle("eth_withoutfcs", d.NewHandle(protoEth, dissectEth))

	// EtherResolver, when set, returns a vendor-qualified name for a MAC
	// address ("Apple_1c:22:01") or "" when unknown.
	EtherResolver func(mac []byte) string
)

func init() {
	EncapTable.Add(uint64(pcapio.LinkEthernet), ethHandle)
}

func resolveEther(b []byte) string {
	if EtherResolver != nil {
		if s := EtherResolver(b); s != "" {
			return s
		}
	}
	return d.FormatEther(b)
}

func addEthAddr(tree *d.Node, tvb *d.Tvb, off int, hf, hfRes, hfOUI, hfLG, hfIG *d.FieldDef, title string) []byte {
	b := tvb.Bytes(off, 6)
	res := resolveEther(b)
	n, _ := tree.AddBytes(hf, tvb, off, 6)
	if res != d.FormatEther(b) {
		n.SetText("%s: %s (%s)", title, res, d.FormatEther(b))
	}
	sub := n
	a, _ := sub.AddBytes(hfEthAddr, tvb, off, 6)
	if res != d.FormatEther(b) {
		a.SetText("Address: %s (%s)", res, d.FormatEther(b))
	}
	sub.AddValue(hfRes, tvb, off, 6, d.StringValue(res)).SetGenerated().SetHidden()
	sub.AddValue(hfEthAddrRes, tvb, off, 6, d.StringValue(res)).SetGenerated().SetHidden()
	oui := uint64(b[0])<<16 | uint64(b[1])<<8 | uint64(b[2])
	sub.AddUintValue(hfOUI, tvb, off, 3, oui).SetHidden()
	sub.AddBits(hfLG, tvb, off, 3, oui)
	sub.AddBits(hfIG, tvb, off, 3, oui)
	sub.AddBits(hfEthLG, tvb, off, 3, oui).SetHidden()
	sub.AddBits(hfEthIG, tvb, off, 3, oui).SetHidden()
	return b
}

func dissectEth(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 14 {
		tvb.Bytes(0, 14) // raises a bounds error
	}
	typ := tvb.U16(12)
	et := tree.AddProtocol(protoEth, tvb, 0, 14)
	pi.SetProtocol("Ethernet")
	dst := addEthAddr(et, tvb, 0, hfEthDst, hfEthDstRes, hfEthDstOUI, hfEthDstLG, hfEthDstIG, "Destination")
	src := addEthAddr(et, tvb, 6, hfEthSrc, hfEthSrcRes, hfEthSrcOUI, hfEthSrcLG, hfEthSrcIG, "Source")
	if !pi.InErrorPkt {
		pi.SetDLAddrs(d.EtherAddr(src), d.EtherAddr(dst))
	}
	if typ <= 1500 {
		// IEEE 802.3 with an LLC payload.
		et.SetText("IEEE 802.3 Ethernet, Src: %s, Dst: %s", resolveEther(src), resolveEther(dst))
		et.AddUint(hfEthLen, tvb, 12, 2)
		plen := int(typ)
		payload := tvb.Sub(14, min(plen, tvb.Reported()-14))
		n := pi.Call(llcHandle, payload, tree)
		addEthTrailer(et, tvb, 14+n, pi)
		return tvb.Len()
	}
	et.SetText("Ethernet II, Src: %s, Dst: %s", resolveEther(src), resolveEther(dst))
	tn, _ := et.AddUint(hfEthType, tvb, 12, 2)
	if typ < 1536 {
		tn.AddExpert(eiEthInvalidL, "Invalid length/type: 0x%04x (%d)", typ, typ)
	}
	return 14 + dispatchEtherType(typ, tvb.Sub(14, -1), pi, tree, et, tvb, 14)
}

// dispatchEtherType hands the payload to the ethertype table and shows
// padding/trailer bytes the payload dissector did not consume.
func dispatchEtherType(typ uint16, payload *d.Tvb, pi *d.PacketInfo, tree, owner *d.Node, outer *d.Tvb, base int) int {
	pi.Protocols = append(pi.Protocols, "ethertype")
	n, ok := EtherTypeTable.Try(uint64(typ), payload, pi, tree)
	if !ok {
		pi.SetProtocol("0x" + hex4(typ))
		pi.Call(DataHandle, payload, tree)
		return payload.Len()
	}
	if owner != nil {
		addEthTrailer(owner, outer, base+n, pi)
	}
	return payload.Len()
}

func addEthTrailer(et *d.Node, tvb *d.Tvb, off int, pi *d.PacketInfo) {
	rem := tvb.Remaining(off)
	if rem <= 0 {
		return
	}
	fcsLen := 0
	if int(pi.Iface) < len(pi.Sess.Interfaces) && pi.Sess.Interfaces[pi.Iface].FCSLen == 4 {
		fcsLen = 4
	}
	body := rem - fcsLen
	if body > 0 {
		// Frames shorter than 60 bytes are padded; anything else is a trailer.
		if off < 60 {
			pad := min(body, 60-off)
			et.AddBytes(hfEthPadding, tvb, off, pad)
			off += pad
			body -= pad
		}
		if body > 0 {
			et.AddBytes(hfEthTrailer, tvb, off, body)
			off += body
		}
	}
	if fcsLen == 4 && tvb.Has(off, 4) {
		et.AddUint(hfEthFCS, tvb, off, 4)
	}
}

func hex4(v uint16) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[v>>12], digits[v>>8&15], digits[v>>4&15], digits[v&15]})
}

// ---- 802.1Q VLAN ----

var (
	protoVLAN   = d.RegisterProto("802.1Q Virtual LAN", "VLAN", "vlan")
	hfVLANPrio  = protoVLAN.Field("vlan.priority", "Priority", d.FtUint16, d.WithMask(0xe000), d.WithVS(map[uint64]string{0: "Best Effort (default)", 1: "Background", 2: "Excellent Effort", 3: "Critical Applications", 4: "Video, < 100ms latency and jitter", 5: "Voice, < 10ms latency and jitter", 6: "Internetwork Control", 7: "Network Control"}))
	hfVLANDEI   = protoVLAN.Field("vlan.dei", "DEI", d.FtBool, d.WithMask(0x1000), d.WithParentBits(16), d.WithTFS(&d.TrueFalse{True: "Eligible", False: "Ineligible"}))
	hfVLANID    = protoVLAN.Field("vlan.id", "ID", d.FtUint16, d.WithMask(0x0fff))
	hfVLANEtype = protoVLAN.Field("vlan.etype", "Type", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(EtherTypes))
	hfVLANLen   = protoVLAN.Field("vlan.len", "Length", d.FtUint16)
)

func init() {
	h := d.NewHandle(protoVLAN, dissectVLAN)
	EtherTypeTable.Add(0x8100, h)
	EtherTypeTable.Add(0x88a8, h)
	EtherTypeTable.Add(0x9100, h)
}

func dissectVLAN(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	tci := tvb.U16(0)
	typ := tvb.U16(2)
	prio, dei, id := tci>>13, tci>>12&1, tci&0xfff
	vt := tree.AddProtocol(protoVLAN, tvb, 0, 4)
	vt.SetText("802.1Q Virtual LAN, PRI: %d, DEI: %d, ID: %d", prio, dei, id)
	pi.SetProtocol("802.1Q")
	pi.SetInfof("PRI: %d  DEI: %d  ID: %d", prio, dei, id)
	vt.AddBits(hfVLANPrio, tvb, 0, 2, uint64(tci))
	vt.AddBits(hfVLANDEI, tvb, 0, 2, uint64(tci))
	vt.AddBits(hfVLANID, tvb, 0, 2, uint64(tci))
	if typ <= 1500 {
		vt.AddUint(hfVLANLen, tvb, 2, 2)
		pi.Call(llcHandle, tvb.Sub(4, min(int(typ), tvb.Reported()-4)), tree)
		return tvb.Len()
	}
	vt.AddUint(hfVLANEtype, tvb, 2, 2)
	dispatchEtherType(typ, tvb.Sub(4, -1), pi, tree, nil, nil, 0)
	return tvb.Len()
}

// ---- IEEE 802.2 LLC / SNAP ----

var (
	sapNames = map[uint64]string{0x00: "NULL LSAP", 0x02: "LLC Sub-Layer Management Individual", 0x06: "TCP/IP",
		0x42: "Spanning Tree BPDU", 0x7e: "ISO 8208 (X.25 over 802.2)", 0x98: "ARP", 0xaa: "SNAP",
		0xe0: "NetWare", 0xf0: "NetBIOS", 0xf4: "LAN Management", 0xfe: "ISO Network Layer (OSLAN 1)", 0xff: "Global LSAP"}
	protoLLC    = d.RegisterProto("Logical-Link Control", "LLC", "llc")
	hfLLCDSAP   = protoLLC.Field("llc.dsap", "DSAP", d.FtUint8, d.WithBase(d.BaseHex), d.WithVS(sapNames))
	hfLLCSSAP   = protoLLC.Field("llc.ssap", "SSAP", d.FtUint8, d.WithBase(d.BaseHex), d.WithVS(sapNames))
	hfLLCCtrl   = protoLLC.Field("llc.control", "Control field", d.FtUint8, d.WithBase(d.BaseHex))
	hfLLCOUI    = protoLLC.Field("llc.oui", "Organization Code", d.FtUint24, d.WithBase(d.BaseHex), d.WithVS(map[uint64]string{0: "Encapsulated Ethernet", 0x00000c: "Cisco", 0x0080c2: "IEEE 802.1"}))
	hfLLCPID    = protoLLC.Field("llc.pid", "PID", d.FtUint16, d.WithBase(d.BaseHex))
	hfLLCType   = protoLLC.Field("llc.type", "Type", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(EtherTypes))
	llcHandle   = d.RegisterHandle("llc", d.NewHandle(protoLLC, dissectLLC))
	LLCSAPTable = d.Table("llc.dsap")
	// LLCCiscoPID dispatches SNAP frames with the Cisco OUI (CDP, ...).
	LLCCiscoPID = d.Table("llc.cisco_pid")
)

func dissectLLC(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	dsap, ssap, ctrl := tvb.U8(0), tvb.U8(1), tvb.U8(2)
	lt := tree.AddProtocol(protoLLC, tvb, 0, 3)
	pi.SetProtocol("LLC")
	lt.AddUint(hfLLCDSAP, tvb, 0, 1)
	lt.AddUint(hfLLCSSAP, tvb, 1, 1)
	lt.AddUint(hfLLCCtrl, tvb, 2, 1)
	if dsap == 0xaa && ssap == 0xaa {
		oui := tvb.U24(3)
		pid := tvb.U16(6)
		lt.SetLen(8)
		lt.AddUint(hfLLCOUI, tvb, 3, 3)
		if oui == 0 {
			lt.AddUint(hfLLCType, tvb, 6, 2)
			dispatchEtherType(pid, tvb.Sub(8, -1), pi, tree, nil, nil, 0)
			return tvb.Len()
		}
		lt.AddUint(hfLLCPID, tvb, 6, 2)
		if oui == 0x00000c {
			if _, ok := LLCCiscoPID.Try(uint64(pid), tvb.Sub(8, -1), pi, tree); ok {
				return tvb.Len()
			}
		}
		pi.Call(DataHandle, tvb.Sub(8, -1), tree)
		return tvb.Len()
	}
	pi.SetInfof("S, func=%s; SNAP, %s", "UI", sapNames[uint64(dsap)])
	_ = ctrl
	if _, ok := LLCSAPTable.Try(uint64(dsap), tvb.Sub(3, -1), pi, tree); !ok {
		pi.Call(DataHandle, tvb.Sub(3, -1), tree)
	}
	return tvb.Len()
}
