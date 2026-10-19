package proto

import (
	d "github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/pcapio"
)

// ---- GRE ----

var (
	greProtos = func() map[uint64]string {
		m := map[uint64]string{0x880b: "PPP", 0x6558: "Transparent Ethernet bridging", 0x88be: "ERSPAN", 0x22eb: "ERSPAN type III", 0x8847: "MPLS label switched packet"}
		for k, v := range EtherTypes {
			if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
		return m
	}()
	protoGRE      = d.RegisterProto("Generic Routing Encapsulation", "GRE", "gre")
	hfGREFlags    = protoGRE.Field("gre.flags_and_version", "Flags and Version", d.FtUint16, d.WithBase(d.BaseHex))
	hfGREFlagC    = protoGRE.Field("gre.flags.checksum", "Checksum Bit", d.FtBool, d.WithMask(0x8000), d.WithParentBits(16), d.WithTFS(d.TFSYesNo))
	hfGREFlagR    = protoGRE.Field("gre.flags.routing", "Routing Bit", d.FtBool, d.WithMask(0x4000), d.WithParentBits(16), d.WithTFS(d.TFSYesNo))
	hfGREFlagK    = protoGRE.Field("gre.flags.key", "Key Bit", d.FtBool, d.WithMask(0x2000), d.WithParentBits(16), d.WithTFS(d.TFSYesNo))
	hfGREFlagS    = protoGRE.Field("gre.flags.sequence_number", "Sequence Number Bit", d.FtBool, d.WithMask(0x1000), d.WithParentBits(16), d.WithTFS(d.TFSYesNo))
	hfGREFlagA    = protoGRE.Field("gre.flags.ack", "Acknowledgment", d.FtBool, d.WithMask(0x0080), d.WithParentBits(16), d.WithTFS(d.TFSYesNo))
	hfGREVersion  = protoGRE.Field("gre.flags.version", "Version", d.FtUint16, d.WithMask(0x0007), d.WithVS(map[uint64]string{0: "GRE", 1: "Enhanced GRE"}))
	hfGREProto    = protoGRE.Field("gre.proto", "Protocol Type", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(greProtos))
	hfGREChecksum = protoGRE.Field("gre.checksum", "Checksum", d.FtUint16, d.WithBase(d.BaseHex))
	hfGREOffset   = protoGRE.Field("gre.offset", "Offset", d.FtUint16)
	hfGREKey      = protoGRE.Field("gre.key", "Key", d.FtUint32, d.WithBase(d.BaseHex))
	hfGRESeq      = protoGRE.Field("gre.sequence_number", "Sequence Number", d.FtUint32)
	hfGREAck      = protoGRE.Field("gre.ack_number", "Acknowledgment Number", d.FtUint32)
	hfGREPayLen   = protoGRE.Field("gre.payload_length", "Payload Length", d.FtUint16)
	hfGRECallID   = protoGRE.Field("gre.call_id", "Call ID", d.FtUint16)
	// GREProtoTable dispatches GRE payloads (falls back to ethertypes).
	GREProtoTable = d.Table("gre.proto")
)

func init() {
	IPProtoTable.Add(47, d.NewHandle(protoGRE, dissectGRE))
	GREProtoTable.Add(0x6558, ethHandle)
	GREProtoTable.Add(0x880b, pppHandle)
}

func dissectGRE(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	fv := tvb.U16(0)
	typ := tvb.U16(2)
	gt := tree.AddProtocol(protoGRE, tvb, 0, 4)
	pi.SetProtocol("GRE")
	fn := gt.AddUintValue(hfGREFlags, tvb, 0, 2, uint64(fv))
	for _, f := range []*d.FieldDef{hfGREFlagC, hfGREFlagR, hfGREFlagK, hfGREFlagS, hfGREFlagA, hfGREVersion} {
		fn.AddBits(f, tvb, 0, 2, uint64(fv))
	}
	gt.AddUint(hfGREProto, tvb, 2, 2)
	off := 4
	version := fv & 7
	if version == 1 {
		gt.AddUint(hfGREPayLen, tvb, 4, 2)
		gt.AddUint(hfGRECallID, tvb, 6, 2)
		off = 8
	} else if fv&0xc000 != 0 {
		gt.AddUint(hfGREChecksum, tvb, off, 2)
		gt.AddUint(hfGREOffset, tvb, off+2, 2)
		off += 4
	}
	if fv&0x2000 != 0 && version == 0 {
		gt.AddUint(hfGREKey, tvb, off, 4)
		off += 4
	}
	if fv&0x1000 != 0 {
		gt.AddUint(hfGRESeq, tvb, off, 4)
		off += 4
	}
	if fv&0x0080 != 0 && version == 1 {
		gt.AddUint(hfGREAck, tvb, off, 4)
		off += 4
	}
	gt.SetLen(off)
	name := greProtos[uint64(typ)]
	if name == "" {
		name = "0x" + hex4(typ)
	}
	gt.SetText("Generic Routing Encapsulation (%s)", name)
	payload := tvb.Sub(off, -1)
	if payload.Len() == 0 {
		pi.SetInfo("Encapsulated " + name)
		return tvb.Len()
	}
	if _, ok := GREProtoTable.Try(uint64(typ), payload, pi, tree); ok {
		return tvb.Len()
	}
	dispatchEtherType(typ, payload, pi, tree, nil, nil, 0)
	return tvb.Len()
}

// ---- VXLAN ----

var (
	protoVXLAN   = d.RegisterProto("Virtual eXtensible Local Area Network", "VXLAN", "vxlan")
	hfVXLANFlags = protoVXLAN.Field("vxlan.flags", "Flags", d.FtUint16, d.WithBase(d.BaseHex))
	hfVXLANFlagI = protoVXLAN.Field("vxlan.flags.i", "VXLAN Network ID (VNI)", d.FtBool, d.WithMask(0x0800), d.WithParentBits(16), d.WithTFS(d.TFSTrue))
	hfVXLANGBP   = protoVXLAN.Field("vxlan.gbp", "Group Policy ID", d.FtUint16)
	hfVXLANVNI   = protoVXLAN.Field("vxlan.vni", "VXLAN Network Identifier (VNI)", d.FtUint24)
	hfVXLANRes   = protoVXLAN.Field("vxlan.reserved_8", "Reserved", d.FtUint8)
)

func init() {
	h := d.NewHandle(protoVXLAN, dissectVXLAN)
	UDPPortTable.Add(4789, h)
	UDPPortTable.Add(8472, h) // Linux kernel default
}

func dissectVXLAN(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 8 {
		return 0
	}
	flags := tvb.U16(0)
	vt := tree.AddProtocol(protoVXLAN, tvb, 0, 8)
	pi.SetProtocol("VXLAN")
	fn := vt.AddUintValue(hfVXLANFlags, tvb, 0, 2, uint64(flags))
	fn.AddBits(hfVXLANFlagI, tvb, 0, 2, uint64(flags))
	vt.AddUint(hfVXLANGBP, tvb, 2, 2)
	_, vni := vt.AddUint(hfVXLANVNI, tvb, 4, 3)
	vt.AddUint(hfVXLANRes, tvb, 7, 1)
	vt.SetText("Virtual eXtensible Local Area Network, VNI: %d", vni)
	pi.Call(ethHandle, tvb.Sub(8, -1), tree)
	return tvb.Len()
}

// ---- Geneve ----

var (
	protoGeneve   = d.RegisterProto("Generic Network Virtualization Encapsulation", "Geneve", "geneve")
	hfGeneveVer   = protoGeneve.Field("geneve.version", "Version", d.FtUint8, d.WithMask(0xc0))
	hfGeneveOptLn = protoGeneve.Field("geneve.options_length", "Options Length", d.FtUint8, d.WithMask(0x3f))
	hfGeneveOAM   = protoGeneve.Field("geneve.flags.oam", "Operations, Administration and Management Frame", d.FtBool, d.WithMask(0x80), d.WithParentBits(8), d.WithTFS(d.TFSTrue))
	hfGeneveCrit  = protoGeneve.Field("geneve.flags.critical", "Critical Options Present", d.FtBool, d.WithMask(0x40), d.WithParentBits(8), d.WithTFS(d.TFSTrue))
	hfGeneveProto = protoGeneve.Field("geneve.proto_type", "Protocol Type", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(greProtos))
	hfGeneveVNI   = protoGeneve.Field("geneve.vni", "Virtual Network Identifier (VNI)", d.FtUint24, d.WithBase(d.BaseHexDec))
	hfGeneveOpts  = protoGeneve.Field("geneve.options", "Geneve Options", d.FtBytes)
)

func init() {
	UDPPortTable.Add(6081, d.NewHandle(protoGeneve, dissectGeneve))
}

func dissectGeneve(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	b0, b1 := tvb.U8(0), tvb.U8(1)
	optLen := int(b0&0x3f) * 4
	typ := tvb.U16(2)
	gt := tree.AddProtocol(protoGeneve, tvb, 0, 8+optLen)
	pi.SetProtocol("Geneve")
	gt.AddBits(hfGeneveVer, tvb, 0, 1, uint64(b0))
	gt.AddBits(hfGeneveOptLn, tvb, 0, 1, uint64(b0)).AppendText(" (%d bytes)", optLen)
	gt.AddBits(hfGeneveOAM, tvb, 1, 1, uint64(b1))
	gt.AddBits(hfGeneveCrit, tvb, 1, 1, uint64(b1))
	gt.AddUint(hfGeneveProto, tvb, 2, 2)
	_, vni := gt.AddUint(hfGeneveVNI, tvb, 4, 3)
	if optLen > 0 {
		gt.AddBytes(hfGeneveOpts, tvb, 8, optLen)
	}
	gt.SetText("Generic Network Virtualization Encapsulation, VNI: 0x%06x", vni)
	payload := tvb.Sub(8+optLen, -1)
	if typ == 0x6558 {
		pi.Call(ethHandle, payload, tree)
	} else {
		dispatchEtherType(typ, payload, pi, tree, nil, nil, 0)
	}
	return tvb.Len()
}

// ---- MPLS ----

var (
	mplsLabels   = map[uint64]string{0: "IPv4 Explicit-Null", 1: "Router Alert", 2: "IPv6 Explicit-Null", 3: "Implicit-Null", 7: "Entropy Label Indicator", 13: "Generic Associated Channel Label (GAL)", 14: "OAM Alert", 15: "Extension"}
	protoMPLS    = d.RegisterProto("MultiProtocol Label Switching Header", "MPLS", "mpls")
	hfMPLSLabel  = protoMPLS.Field("mpls.label", "MPLS Label", d.FtUint32, d.WithMask(0xfffff000))
	hfMPLSExp    = protoMPLS.Field("mpls.exp", "MPLS Experimental Bits", d.FtUint32, d.WithMask(0x00000e00))
	hfMPLSBottom = protoMPLS.Field("mpls.bottom", "MPLS Bottom Of Label Stack", d.FtBool, d.WithMask(0x00000100), d.WithParentBits(32), d.WithTFS(d.TFSTrue))
	hfMPLSTTL    = protoMPLS.Field("mpls.ttl", "MPLS TTL", d.FtUint32, d.WithMask(0x000000ff))
	hfMPLSCW     = protoMPLS.Field("mpls.cw.control", "MPLS Control Word", d.FtUint32, d.WithBase(d.BaseHex))
	mplsHandle   = d.RegisterHandle("mpls", d.NewHandle(protoMPLS, dissectMPLS))
)

func init() {
	EtherTypeTable.Add(0x8847, mplsHandle)
	EtherTypeTable.Add(0x8848, mplsHandle)
	IPProtoTable.Add(137, mplsHandle)
	UDPPortTable.Add(6635, mplsHandle)
}

func dissectMPLS(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	off := 0
	pi.SetProtocol("MPLS")
	for {
		w := tvb.U32(off)
		label, exp, bos, ttl := w>>12, (w>>9)&7, w&0x100 != 0, w&0xff
		mt := tree.AddProtocol(protoMPLS, tvb, off, 4)
		mt.SetText("MultiProtocol Label Switching Header, Label: %d, Exp: %d, S: %d, TTL: %d", label, exp, b2i(bos), ttl)
		ln := mt.AddBits(hfMPLSLabel, tvb, off, 4, uint64(w))
		if name, ok := mplsLabels[uint64(label)]; ok {
			ln.AppendText(" (%s)", name)
		}
		mt.AddBits(hfMPLSExp, tvb, off, 4, uint64(w))
		mt.AddBits(hfMPLSBottom, tvb, off, 4, uint64(w))
		mt.AddBits(hfMPLSTTL, tvb, off, 4, uint64(w))
		off += 4
		if bos {
			break
		}
	}
	payload := tvb.Sub(off, -1)
	if payload.Len() == 0 {
		return tvb.Len()
	}
	switch payload.U8(0) >> 4 {
	case 4:
		pi.Call(ipHandle, payload, tree)
	case 6:
		pi.Call(ipv6Handle, payload, tree)
	case 0:
		// Pseudowire with a control word, carrying Ethernet.
		cw := payload.Sub(0, 4)
		tree.AddUint(hfMPLSCW, cw, 0, 4)
		pi.Call(ethHandle, payload.Sub(4, -1), tree)
	default:
		pi.Call(ethHandle, payload, tree)
	}
	return tvb.Len()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---- PPP and PPPoE ----

var (
	pppProtos = map[uint64]string{0x0021: "Internet Protocol version 4", 0x0057: "Internet Protocol version 6",
		0x0281: "MPLS Unicast", 0x0283: "MPLS Multicast", 0x002b: "Novell IPX", 0x003d: "PPP Multilink",
		0xc021: "Link Control Protocol", 0x8021: "Internet Protocol Control Protocol", 0x8057: "IPv6 Control Protocol",
		0xc023: "Password Authentication Protocol", 0xc223: "Challenge Handshake Authentication Protocol",
		0xc025: "Link Quality Report", 0x80fd: "Compression Control Protocol", 0x00fd: "PPP Compressed Datagram",
		0xc227: "PPP Extensible Authentication Protocol"}
	protoPPP     = d.RegisterProto("Point-to-Point Protocol", "PPP", "ppp")
	hfPPPAddr    = protoPPP.Field("ppp.address", "Address", d.FtUint8, d.WithBase(d.BaseHex))
	hfPPPControl = protoPPP.Field("ppp.control", "Control", d.FtUint8, d.WithBase(d.BaseHex))
	hfPPPProto   = protoPPP.Field("ppp.protocol", "Protocol", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(pppProtos))
	pppHandle    = d.RegisterHandle("ppp", d.NewHandle(protoPPP, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		return dissectPPP(tvb, pi, tree, true)
	}))
	// PPPProtoTable dispatches PPP payloads.
	PPPProtoTable = d.Table("ppp.protocol")

	pppoeCodes = map[uint64]string{0x00: "Session Data", 0x09: "Active Discovery Initiation (PADI)",
		0x07: "Active Discovery Offer (PADO)", 0x19: "Active Discovery Request (PADR)",
		0x65: "Active Discovery Session-confirmation (PADS)", 0xa7: "Active Discovery Terminate (PADT)"}
	pppoeShort = map[uint64]string{0x09: "PADI", 0x07: "PADO", 0x19: "PADR", 0x65: "PADS", 0xa7: "PADT"}
	pppoeTags  = map[uint64]string{0x0000: "End-Of-List", 0x0101: "Service-Name", 0x0102: "AC-Name", 0x0103: "Host-Uniq",
		0x0104: "AC-Cookie", 0x0105: "Vendor-Specific", 0x0110: "Relay-Session-Id", 0x0120: "PPP-Max-Payload",
		0x0201: "Service-Name-Error", 0x0202: "AC-System-Error", 0x0203: "Generic-Error"}
	protoPPPoED    = d.RegisterProto("PPP-over-Ethernet Discovery", "PPPoED", "pppoed")
	protoPPPoES    = d.RegisterProto("PPP-over-Ethernet Session", "PPPoES", "pppoes")
	protoPPPoE     = d.RegisterProto("PPP-over-Ethernet", "PPPoE", "pppoe")
	hfPPPoEVersion = protoPPPoE.Field("pppoe.version", "Version", d.FtUint8, d.WithMask(0xf0))
	hfPPPoEType    = protoPPPoE.Field("pppoe.type", "Type", d.FtUint8, d.WithMask(0x0f))
	hfPPPoECode    = protoPPPoE.Field("pppoe.code", "Code", d.FtUint8, d.WithBase(d.BaseHex), d.WithVS(pppoeCodes))
	hfPPPoESession = protoPPPoE.Field("pppoe.session_id", "Session ID", d.FtUint16, d.WithBase(d.BaseHex))
	hfPPPoELen     = protoPPPoE.Field("pppoe.payload_length", "Payload Length", d.FtUint16)
	hfPPPoEDTag    = protoPPPoED.Field("pppoed.tag", "Tag", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(pppoeTags))
	hfPPPoEDTagLen = protoPPPoED.Field("pppoed.tag_length", "Tag Length", d.FtUint16)
	hfPPPoEDName   = protoPPPoED.Field("pppoed.tags.service_name", "Service-Name", d.FtString)
	hfPPPoEDACName = protoPPPoED.Field("pppoed.tags.ac_name", "AC-Name", d.FtString)
	hfPPPoEDTagVal = protoPPPoED.Field("pppoed.tag_value", "Tag Value", d.FtBytes)
)

func init() {
	EncapTable.Add(uint64(pcapio.LinkPPP), pppHandle)
	EncapTable.Add(uint64(pcapio.LinkPPPEther), pppHandle)
	PPPProtoTable.Add(0x0021, ipHandle)
	PPPProtoTable.Add(0x0057, ipv6Handle)
	PPPProtoTable.Add(0x0281, mplsHandle)
	PPPProtoTable.Add(0x0283, mplsHandle)
	EtherTypeTable.Add(0x8863, d.NewHandle(protoPPPoED, dissectPPPoEDiscovery))
	EtherTypeTable.Add(0x8864, d.NewHandle(protoPPPoES, dissectPPPoESession))
}

func dissectPPP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node, hdlc bool) int {
	pt := tree.AddProtocol(protoPPP, tvb, 0, 2)
	pi.SetProtocol("PPP")
	off := 0
	if hdlc && tvb.Len() >= 2 && tvb.U8(0) == 0xff && tvb.U8(1) == 0x03 {
		pt.AddUint(hfPPPAddr, tvb, 0, 1)
		pt.AddUint(hfPPPControl, tvb, 1, 1)
		off = 2
	}
	var proto uint16
	if tvb.U8(off)&1 != 0 {
		// Protocol field compression: one byte.
		proto = uint16(tvb.U8(off))
		pt.AddUintValue(hfPPPProto, tvb, off, 1, uint64(proto))
		off++
	} else {
		proto = tvb.U16(off)
		pt.AddUint(hfPPPProto, tvb, off, 2)
		off += 2
	}
	pt.SetLen(off)
	payload := tvb.Sub(off, -1)
	if _, ok := PPPProtoTable.Try(uint64(proto), payload, pi, tree); !ok {
		name := pppProtos[uint64(proto)]
		if name == "" {
			name = "0x" + hex4(proto)
		}
		pi.SetProtocol("PPP")
		pi.SetInfo(name)
		pi.Call(DataHandle, payload, tree)
	}
	return tvb.Len()
}

func pppoeHeader(tvb *d.Tvb, pt *d.Node) (code uint64, session uint64, plen int) {
	vt := uint64(tvb.U8(0))
	pt.AddBits(hfPPPoEVersion, tvb, 0, 1, vt)
	pt.AddBits(hfPPPoEType, tvb, 0, 1, vt)
	_, code = pt.AddUint(hfPPPoECode, tvb, 1, 1)
	_, session = pt.AddUint(hfPPPoESession, tvb, 2, 2)
	_, l := pt.AddUint(hfPPPoELen, tvb, 4, 2)
	return code, session, int(l)
}

func dissectPPPoEDiscovery(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	pt := tree.AddProtocol(protoPPPoED, tvb, 0, -1)
	pi.SetProtocol("PPPoED")
	code, _, plen := pppoeHeader(tvb, pt)
	info := pppoeCodes[code]
	if info == "" {
		info = "Unknown code"
	}
	pi.SetInfo(info)
	end := min(6+plen, tvb.Len())
	for off := 6; off+4 <= end; {
		typ := tvb.U16(off)
		l := int(tvb.U16(off + 2))
		name := pppoeTags[uint64(typ)]
		if name == "" {
			name = "Unknown"
		}
		tn := pt.AddText(tvb, off, 4+l, "%s", name)
		tn.AddUint(hfPPPoEDTag, tvb, off, 2)
		tn.AddUint(hfPPPoEDTagLen, tvb, off+2, 2)
		if l > 0 && off+4+l <= end {
			switch typ {
			case 0x0101:
				_, s := tn.AddString(hfPPPoEDName, tvb, off+4, l)
				tn.AppendText(": %s", s)
			case 0x0102:
				_, s := tn.AddString(hfPPPoEDACName, tvb, off+4, l)
				tn.AppendText(": %s", s)
			default:
				tn.AddBytes(hfPPPoEDTagVal, tvb, off+4, l)
			}
		}
		off += 4 + l
		if typ == 0 {
			break
		}
	}
	return tvb.Len()
}

func dissectPPPoESession(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	pt := tree.AddProtocol(protoPPPoES, tvb, 0, 6)
	pi.SetProtocol("PPPoES")
	_, _, plen := pppoeHeader(tvb, pt)
	payload := tvb.Sub(6, min(plen, tvb.Reported()-6))
	pi.Call(&d.Handle{Proto: protoPPP, Fn: func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		return dissectPPP(tvb, pi, tree, false)
	}}, payload, tree)
	return 6 + payload.Len()
}
