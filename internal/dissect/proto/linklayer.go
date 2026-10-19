package proto

import (
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/pcapio"
)

// ---- BSD loopback (LINKTYPE_NULL) and OpenBSD loopback (LINKTYPE_LOOP) ----

var (
	afNames = map[uint64]string{2: "IP", 7: "OSI", 16: "AppleTalk", 23: "IPX", 24: "IPv6",
		28: "IPv6", 30: "IPv6", 10: "IPv6"}
	protoNull    = d.RegisterProto("Null/Loopback", "NULL", "null")
	hfNullFamily = protoNull.Field("null.family", "Family", d.FtUint32, d.WithVS(afNames))
	hfNullType   = protoNull.Field("null.type", "Type", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(EtherTypes))
	protoRaw     = d.RegisterProto("Raw packet data", "Raw", "raw")
	rawHandle    = d.NewHandle(protoRaw, dissectRaw)
)

func init() {
	EncapTable.Add(uint64(pcapio.LinkNull), d.NewHandle(protoNull, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		return dissectNull(tvb, pi, tree, false)
	}))
	EncapTable.Add(uint64(pcapio.LinkLoop), d.NewHandle(protoNull, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		return dissectNull(tvb, pi, tree, true)
	}))
	EncapTable.Add(uint64(pcapio.LinkRaw), rawHandle)
	EncapTable.Add(uint64(pcapio.LinkIPv4), rawHandle)
	EncapTable.Add(uint64(pcapio.LinkIPv6), rawHandle)
}

func dissectNull(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node, network bool) int {
	nt := tree.AddProtocol(protoNull, tvb, 0, 4)
	pi.SetProtocol("NULL")
	// Some captures store a PPP-style ethertype in the first two bytes.
	if !network && tvb.U16(0) == 0xff03 {
		return pi.Call(DataHandle, tvb, tree)
	}
	var fam uint64
	if network {
		fam = uint64(tvb.U32(0))
		nt.AddUint(hfNullFamily, tvb, 0, 4)
	} else {
		fam = uint64(tvb.U32LE(0))
		if fam > 0xffff {
			fam = uint64(tvb.U32(0))
			nt.AddUint(hfNullFamily, tvb, 0, 4)
		} else {
			nt.AddUintLE(hfNullFamily, tvb, 0, 4)
		}
	}
	payload := tvb.Sub(4, -1)
	switch fam {
	case 2:
		dispatchEtherType(0x0800, payload, pi, tree, nil, nil, 0)
	case 10, 24, 28, 30:
		dispatchEtherType(0x86dd, payload, pi, tree, nil, nil, 0)
	default:
		pi.Call(DataHandle, payload, tree)
	}
	return tvb.Len()
}

func dissectRaw(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	rt := tree.AddProtocol(protoRaw, tvb, 0, 0)
	rt.SetText("Raw packet data")
	rt.AddText(nil, 0, 0, "No link information available")
	pi.SetProtocol("Raw")
	switch tvb.U8(0) >> 4 {
	case 4:
		dispatchEtherType(0x0800, tvb, pi, tree, nil, nil, 0)
	case 6:
		dispatchEtherType(0x86dd, tvb, pi, tree, nil, nil, 0)
	default:
		pi.Call(DataHandle, tvb, tree)
	}
	return tvb.Len()
}

// ---- Linux cooked capture v1 / v2 ----

var (
	sllPktTypes = map[uint64]string{0: "Unicast to us", 1: "Broadcast", 2: "Multicast",
		3: "Unicast to another host", 4: "Sent by us"}
	arpHrd = map[uint64]string{1: "Ethernet", 6: "IEEE 802", 24: "IEEE 1394", 32: "InfiniBand",
		512: "PPP", 768: "IPIP tunnel", 772: "Loopback", 776: "IPv6-in-IPv4", 778: "IP GRE tunnel",
		801: "IEEE 802.11", 803: "IEEE 802.11 + radiotap", 824: "Netlink", 65534: "None", 65535: "Void"}
	protoSLL     = d.RegisterProto("Linux cooked capture v1", "SLL", "sll")
	hfSLLPktType = protoSLL.Field("sll.pkttype", "Packet type", d.FtUint16, d.WithVS(sllPktTypes))
	hfSLLHAType  = protoSLL.Field("sll.hatype", "Link-layer address type", d.FtUint16, d.WithVS(arpHrd))
	hfSLLHALen   = protoSLL.Field("sll.halen", "Link-layer address length", d.FtUint16)
	hfSLLSrcEth  = protoSLL.Field("sll.src.eth", "Source", d.FtEther)
	hfSLLSrcOth  = protoSLL.Field("sll.src.other", "Source", d.FtBytes)
	hfSLLUnused  = protoSLL.Field("sll.unused", "Unused", d.FtBytes)
	hfSLLEtype   = protoSLL.Field("sll.etype", "Protocol", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(EtherTypes))
	hfSLLLtype   = protoSLL.Field("sll.ltype", "Protocol", d.FtUint16, d.WithBase(d.BaseHex),
		d.WithVS(map[uint64]string{1: "Novell 802.3", 2: "802.2 LLC", 3: "Ethernet", 4: "802.2 LLC", 0xc: "CAN", 0xd: "CAN FD", 0xf: "CAN XL"}))
	hfSLLIfIndex  = protoSLL.Field("sll.ifindex", "Interface index", d.FtUint32)
	hfSLLReserved = protoSLL.Field("sll.reserved", "Reserved", d.FtUint16, d.WithBase(d.BaseHex))
	protoSLL2     = d.RegisterProto("Linux cooked capture v2", "SLL2", "sll2")
)

func init() {
	EncapTable.Add(uint64(pcapio.LinkLinuxSLL), d.NewHandle(protoSLL, dissectSLL))
	EncapTable.Add(uint64(pcapio.LinkLinuxSLL2), d.NewHandle(protoSLL2, dissectSLL2))
}

func sllAddr(st *d.Node, tvb *d.Tvb, off int, hatype, halen int) {
	if halen == 6 && (hatype == 1 || hatype == 772 || hatype == 6) {
		st.AddBytes(hfSLLSrcEth, tvb, off, 6)
		return
	}
	if halen > 0 {
		st.AddBytes(hfSLLSrcOth, tvb, off, min(halen, 8))
	}
}

func sllPayload(proto uint16, tvb *d.Tvb, pi *d.PacketInfo, tree, st *d.Node, off int) {
	payload := tvb.Sub(off, -1)
	if proto <= 1500 {
		st.AddUint(hfSLLLtype, tvb, off-2, 2)
		switch proto {
		case 3:
			pi.Call(ethHandle, payload, tree)
		case 4:
			pi.Call(llcHandle, payload, tree)
		default:
			pi.Call(DataHandle, payload, tree)
		}
		return
	}
	st.AddUint(hfSLLEtype, tvb, off-2, 2)
	dispatchEtherType(proto, payload, pi, tree, nil, nil, 0)
}

func dissectSLL(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	st := tree.AddProtocol(protoSLL, tvb, 0, 16)
	pi.SetProtocol("SLL")
	_, pkt := st.AddUint(hfSLLPktType, tvb, 0, 2)
	_, hatype := st.AddUint(hfSLLHAType, tvb, 2, 2)
	_, halen := st.AddUint(hfSLLHALen, tvb, 4, 2)
	sllAddr(st, tvb, 6, int(hatype), int(halen))
	if halen < 8 {
		st.AddBytes(hfSLLUnused, tvb, 6+int(halen), 8-int(halen))
	}
	if name, ok := sllPktTypes[pkt]; ok && pkt == 4 {
		_ = name
	}
	sllPayload(tvb.U16(14), tvb, pi, tree, st, 16)
	return tvb.Len()
}

func dissectSLL2(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	st := tree.AddProtocol(protoSLL2, tvb, 0, 20)
	pi.SetProtocol("SLL2")
	proto := tvb.U16(0)
	st.AddUint(hfSLLReserved, tvb, 2, 2)
	st.AddUint(hfSLLIfIndex, tvb, 4, 4)
	_, hatype := st.AddUint(hfSLLHAType, tvb, 8, 2)
	st.AddUint(hfSLLPktType, tvb, 10, 1)
	_, halen := st.AddUint(hfSLLHALen, tvb, 11, 1)
	sllAddr(st, tvb, 12, int(hatype), int(halen))
	payload := tvb.Sub(20, -1)
	if proto <= 1500 {
		st.AddUint(hfSLLLtype, tvb, 0, 2)
		switch proto {
		case 3:
			pi.Call(ethHandle, payload, tree)
		case 4:
			pi.Call(llcHandle, payload, tree)
		default:
			pi.Call(DataHandle, payload, tree)
		}
		return tvb.Len()
	}
	st.AddUint(hfSLLEtype, tvb, 0, 2)
	dispatchEtherType(proto, payload, pi, tree, nil, nil, 0)
	return tvb.Len()
}

// ---- Apple PKTAP ----

var (
	protoPKTAP    = d.RegisterProto("PKTAP packet capture", "PKTAP", "pktap")
	hfPktapHdrLen = protoPKTAP.Field("pktap.hdrlen", "Header length", d.FtUint32)
	hfPktapRecTyp = protoPKTAP.Field("pktap.rectype", "Record type", d.FtUint32, d.WithVS(map[uint64]string{0: "None", 1: "Packet"}))
	hfPktapDLT    = protoPKTAP.Field("pktap.dlt", "DLT", d.FtUint32)
	hfPktapIfName = protoPKTAP.Field("pktap.ifname", "Interface name", d.FtString)
	hfPktapFlags  = protoPKTAP.Field("pktap.flags", "Flags", d.FtUint32, d.WithBase(d.BaseHex))
	hfPktapPFam   = protoPKTAP.Field("pktap.pfamily", "Protocol family", d.FtUint32)
	hfPktapLLHdr  = protoPKTAP.Field("pktap.llhdrlen", "Link-layer header length", d.FtUint32)
	hfPktapLLTrl  = protoPKTAP.Field("pktap.lltrlrlen", "Link-layer trailer length", d.FtUint32)
	hfPktapPID    = protoPKTAP.Field("pktap.pid", "Process ID", d.FtInt32)
	hfPktapCmd    = protoPKTAP.Field("pktap.cmdname", "Command name", d.FtString)
	hfPktapSvc    = protoPKTAP.Field("pktap.svc_class", "Service class", d.FtUint32)
	hfPktapIfType = protoPKTAP.Field("pktap.iftype", "Interface type", d.FtUint16)
	hfPktapIfUnit = protoPKTAP.Field("pktap.ifunit", "Interface unit", d.FtUint16)
	hfPktapEPID   = protoPKTAP.Field("pktap.epid", "Effective process ID", d.FtInt32)
	hfPktapECmd   = protoPKTAP.Field("pktap.ecmdname", "Effective command name", d.FtString)
)

func init() {
	EncapTable.Add(uint64(pcapio.LinkPKTAP), d.NewHandle(protoPKTAP, dissectPKTAP))
	// Apple's libpcap reports DLT_PKTAP as DLT_USER2 (149) in some files.
	EncapTable.Add(149, d.NewHandle(protoPKTAP, dissectPKTAP))
}

// dltToLinkType maps the BSD DLT values found inside PKTAP headers.
func dltToLinkType(dlt uint32) pcapio.LinkType {
	switch dlt {
	case 12, 14:
		return pcapio.LinkRaw
	}
	return pcapio.LinkType(dlt)
}

func cstr(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func dissectPKTAP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	hlen := int(tvb.U32LE(0))
	if hlen < 108 || hlen > tvb.Len() {
		return pi.Call(DataHandle, tvb, tree)
	}
	pt := tree.AddProtocol(protoPKTAP, tvb, 0, hlen)
	pi.SetProtocol("PKTAP")
	pt.AddUintLE(hfPktapHdrLen, tvb, 0, 4)
	_, rectype := pt.AddUintLE(hfPktapRecTyp, tvb, 4, 4)
	_, dlt := pt.AddUintLE(hfPktapDLT, tvb, 8, 4)
	ifname := cstr(tvb.Bytes(12, 24))
	pt.AddValue(hfPktapIfName, tvb, 12, 24, d.StringValue(ifname))
	pt.AddUintLE(hfPktapFlags, tvb, 36, 4)
	pt.AddUintLE(hfPktapPFam, tvb, 40, 4)
	pt.AddUintLE(hfPktapLLHdr, tvb, 44, 4)
	pt.AddUintLE(hfPktapLLTrl, tvb, 48, 4)
	_, pid := pt.AddUintLE(hfPktapPID, tvb, 52, 4)
	cmd := cstr(tvb.Bytes(56, 17))
	pt.AddValue(hfPktapCmd, tvb, 56, 17, d.StringValue(cmd))
	pt.AddUintLE(hfPktapSvc, tvb, 76, 4)
	pt.AddUintLE(hfPktapIfType, tvb, 80, 2)
	pt.AddUintLE(hfPktapIfUnit, tvb, 82, 2)
	_, epid := pt.AddUintLE(hfPktapEPID, tvb, 84, 4)
	ecmd := cstr(tvb.Bytes(88, 17))
	pt.AddValue(hfPktapECmd, tvb, 88, 17, d.StringValue(ecmd))
	pi.PID, pi.ProcName = int32(pid), cmd
	if int32(epid) > 0 && ecmd != "" && ecmd != cmd {
		// Traffic sent on behalf of another process (e.g. nsurlsessiond).
		pi.PID, pi.ProcName = int32(epid), ecmd
	}
	if cmd != "" {
		pt.AppendText(", %s (%d)", pi.ProcName, pi.PID)
	}
	payload := tvb.Sub(hlen, -1)
	if rectype != 1 {
		return pi.Call(DataHandle, payload, tree) + hlen
	}
	if _, ok := EncapTable.Try(uint64(dltToLinkType(uint32(dlt))), payload, pi, tree); !ok {
		pi.Call(DataHandle, payload, tree)
	}
	return tvb.Len()
}

// ---- ARP ----

var (
	arpOps = map[uint64]string{1: "request", 2: "reply", 3: "reply-reverse", 4: "reply-reverse",
		8: "inverse request", 9: "inverse reply", 10: "ARP-NAK"}
	arpOpVS = map[uint64]string{1: "request", 2: "reply", 3: "reverse request", 4: "reverse reply",
		8: "inverse request", 9: "inverse reply", 10: "ARP-NAK"}
	protoARP    = d.RegisterProto("Address Resolution Protocol", "ARP/RARP", "arp")
	hfARPHw     = protoARP.Field("arp.hw.type", "Hardware type", d.FtUint16, d.WithVS(arpHrd))
	hfARPProto  = protoARP.Field("arp.proto.type", "Protocol type", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(EtherTypes))
	hfARPHwSize = protoARP.Field("arp.hw.size", "Hardware size", d.FtUint8)
	hfARPPrSize = protoARP.Field("arp.proto.size", "Protocol size", d.FtUint8)
	hfARPOp     = protoARP.Field("arp.opcode", "Opcode", d.FtUint16, d.WithVS(arpOpVS))
	hfARPGrat   = protoARP.Field("arp.isgratuitous", "Is gratuitous", d.FtBool)
	hfARPProbe  = protoARP.Field("arp.isprobe", "Is probe", d.FtBool)
	hfARPAnnc   = protoARP.Field("arp.isannouncement", "Is announcement", d.FtBool)
	hfARPSrcMAC = protoARP.Field("arp.src.hw_mac", "Sender MAC address", d.FtEther)
	hfARPSrcIP  = protoARP.Field("arp.src.proto_ipv4", "Sender IP address", d.FtIPv4)
	hfARPDstMAC = protoARP.Field("arp.dst.hw_mac", "Target MAC address", d.FtEther)
	hfARPDstIP  = protoARP.Field("arp.dst.proto_ipv4", "Target IP address", d.FtIPv4)
	hfARPSrcHw  = protoARP.Field("arp.src.hw", "Sender hardware address", d.FtBytes)
	hfARPDstHw  = protoARP.Field("arp.dst.hw", "Target hardware address", d.FtBytes)
	hfARPSrcPr  = protoARP.Field("arp.src.proto", "Sender protocol address", d.FtBytes)
	hfARPDstPr  = protoARP.Field("arp.dst.proto", "Target protocol address", d.FtBytes)
)

func init() {
	h := d.NewHandle(protoARP, dissectARP)
	EtherTypeTable.Add(0x0806, h)
	EtherTypeTable.Add(0x8035, h)
}

func dissectARP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	hw, pr := tvb.U16(0), tvb.U16(2)
	hs, ps := int(tvb.U8(4)), int(tvb.U8(5))
	op := tvb.U16(6)
	total := 8 + 2*hs + 2*ps
	at := tree.AddProtocol(protoARP, tvb, 0, total)
	if op == 3 || op == 4 {
		pi.SetProtocol("RARP")
	} else {
		pi.SetProtocol("ARP")
	}
	at.AddUint(hfARPHw, tvb, 0, 2)
	at.AddUint(hfARPProto, tvb, 2, 2)
	at.AddUint(hfARPHwSize, tvb, 4, 1)
	at.AddUint(hfARPPrSize, tvb, 5, 1)
	at.AddUint(hfARPOp, tvb, 6, 2)
	sha, spa := 8, 8+hs
	tha, tpa := 8+hs+ps, 8+2*hs+ps
	isEthIP := hw == 1 && hs == 6 && pr == 0x0800 && ps == 4
	if !isEthIP {
		at.AddBytes(hfARPSrcHw, tvb, sha, hs)
		at.AddBytes(hfARPSrcPr, tvb, spa, ps)
		at.AddBytes(hfARPDstHw, tvb, tha, hs)
		at.AddBytes(hfARPDstPr, tvb, tpa, ps)
		at.SetText("Address Resolution Protocol (%s)", arpOpVS[uint64(op)])
		pi.SetInfof("ARP opcode %d", op)
		return total
	}
	smac, sip := tvb.Bytes(sha, 6), tvb.U32(spa)
	tmac, tip := tvb.Bytes(tha, 6), tvb.U32(tpa)
	gratuitous := sip == tip && (op == 1 || op == 2)
	probe := op == 1 && sip == 0 && isZero(tmac)
	announce := op == 1 && gratuitous && isZero(tmac)
	kind := arpOpVS[uint64(op)]
	switch {
	case probe:
		kind = "ARP Probe"
	case announce:
		kind = "ARP Announcement"
	case gratuitous:
		kind += ", gratuitous"
	}
	at.SetText("Address Resolution Protocol (%s)", kind)
	if gratuitous {
		at.AddGenerated(hfARPGrat, d.BoolValue(true))
	}
	if probe {
		at.AddGenerated(hfARPProbe, d.BoolValue(true))
	}
	if announce {
		at.AddGenerated(hfARPAnnc, d.BoolValue(true))
	}
	at.AddBytes(hfARPSrcMAC, tvb, sha, 6)
	at.AddIPv4(hfARPSrcIP, tvb, spa)
	at.AddBytes(hfARPDstMAC, tvb, tha, 6)
	at.AddIPv4(hfARPDstIP, tvb, tpa)
	switch {
	case probe:
		pi.SetInfof("Who has %s? (ARP Probe)", d.FormatIPv4(tip))
	case announce:
		pi.SetInfof("ARP Announcement for %s", d.FormatIPv4(tip))
	case gratuitous:
		pi.SetInfof("Gratuitous ARP for %s (%s)", d.FormatIPv4(sip), capitalize(arpOpVS[uint64(op)]))
	case op == 1:
		pi.SetInfof("Who has %s? Tell %s", d.FormatIPv4(tip), d.FormatIPv4(sip))
	case op == 2:
		pi.SetInfof("%s is at %s", d.FormatIPv4(sip), resolveEther(smac))
	default:
		pi.SetInfof("ARP %s", arpOps[uint64(op)])
	}
	return total
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
