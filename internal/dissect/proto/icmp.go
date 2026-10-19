package proto

import (
	"fmt"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	icmpTypes = map[uint64]string{0: "Echo (ping) reply", 3: "Destination unreachable", 4: "Source quench (flow control)",
		5: "Redirect", 8: "Echo (ping) request", 9: "Router advertisement", 10: "Router solicitation",
		11: "Time-to-live exceeded", 12: "Parameter problem", 13: "Timestamp request", 14: "Timestamp reply",
		15: "Information request", 16: "Information reply", 17: "Address mask request", 18: "Address mask reply",
		30: "Traceroute", 42: "Extended Echo request", 43: "Extended Echo reply"}
	icmpUnreachCodes = map[uint64]string{0: "Network unreachable", 1: "Host unreachable", 2: "Protocol unreachable",
		3: "Port unreachable", 4: "Fragmentation needed", 5: "Source route failed", 6: "Destination network unknown",
		7: "Destination host unknown", 8: "Source host isolated", 9: "Network administratively prohibited",
		10: "Host administratively prohibited", 11: "Network unreachable for TOS", 12: "Host unreachable for TOS",
		13: "Communication administratively filtered", 14: "Host precedence violation", 15: "Precedence cutoff in effect"}
	icmpRedirectCodes = map[uint64]string{0: "Redirect for network", 1: "Redirect for host", 2: "Redirect for TOS and network", 3: "Redirect for TOS and host"}
	icmpTTLCodes      = map[uint64]string{0: "Time to live exceeded in transit", 1: "Fragment reassembly time exceeded"}
	icmpParamCodes    = map[uint64]string{0: "Pointer indicates the error", 1: "Required option missing", 2: "Bad length"}

	protoICMP      = d.RegisterProto("Internet Control Message Protocol", "ICMP", "icmp")
	hfICMPType     = protoICMP.Field("icmp.type", "Type", d.FtUint8, d.WithVS(icmpTypes))
	hfICMPCode     = protoICMP.Field("icmp.code", "Code", d.FtUint8)
	hfICMPChecksum = protoICMP.Field("icmp.checksum", "Checksum", d.FtUint16, d.WithBase(d.BaseHex))
	hfICMPCkStatus = protoICMP.Field("icmp.checksum.status", "Checksum Status", d.FtUint8, d.WithVS(checksumStatus), d.WithBase(d.BaseNone))
	hfICMPIdent    = protoICMP.Field("icmp.ident", "Identifier (BE)", d.FtUint16, d.WithBase(d.BaseDecHex))
	hfICMPIdentLE  = protoICMP.Field("icmp.ident_le", "Identifier (LE)", d.FtUint16, d.WithBase(d.BaseDecHex))
	hfICMPSeq      = protoICMP.Field("icmp.seq", "Sequence Number (BE)", d.FtUint16, d.WithBase(d.BaseDecHex))
	hfICMPSeqLE    = protoICMP.Field("icmp.seq_le", "Sequence Number (LE)", d.FtUint16, d.WithBase(d.BaseDecHex))
	hfICMPRespIn   = protoICMP.Field("icmp.resp_in", "Response frame", d.FtFrameNum)
	hfICMPRespTo   = protoICMP.Field("icmp.resp_to", "Request frame", d.FtFrameNum)
	hfICMPRespTime = protoICMP.Field("icmp.resptime", "Response time", d.FtDouble, d.WithUnit("ms"))
	hfICMPNoResp   = protoICMP.Field("icmp.no_resp", "No response seen", d.FtNone)
	hfICMPMTU      = protoICMP.Field("icmp.mtu", "MTU of next hop", d.FtUint16)
	hfICMPGateway  = protoICMP.Field("icmp.redir_gw", "Gateway Address", d.FtIPv4)
	hfICMPPointer  = protoICMP.Field("icmp.pointer", "Pointer", d.FtUint32)
	hfICMPUnused   = protoICMP.Field("icmp.unused", "Unused", d.FtBytes)
	hfICMPData     = protoICMP.Field("icmp.data", "Data", d.FtBytes)
	hfICMPTSOrig   = protoICMP.Field("icmp.originate_timestamp", "Originate timestamp", d.FtUint32)
	hfICMPTSRecv   = protoICMP.Field("icmp.receive_timestamp", "Receive timestamp", d.FtUint32)
	hfICMPTSXmit   = protoICMP.Field("icmp.transmit_timestamp", "Transmit timestamp", d.FtUint32)
	eiICMPNoResp   = protoICMP.Expert("icmp.resp_not_found", d.GroupSequence, d.SevWarn, "No response seen to ICMP request")

	icmpHandle = d.NewHandle(protoICMP, dissectICMP)
)

func init() {
	IPProtoTable.Add(1, icmpHandle)
}

// echoKey identifies an echo exchange.
type echoKey struct {
	a, b    d.Address
	id, seq uint16
	v6      bool
}

type echoState struct {
	pending map[echoKey]echoReq
}

type echoReq struct {
	frame uint32
	ts    int64
}

// echoLink is stored per frame: the matching request or reply.
type echoLink struct {
	peer     uint32
	isReply  bool
	respTime float64
}

func echoKeyOf(pi *d.PacketInfo, id, seq uint16, v6, reply bool) echoKey {
	a, b := pi.NetSrc, pi.NetDst
	if reply {
		a, b = b, a
	}
	return echoKey{a: a, b: b, id: id, seq: seq, v6: v6}
}

// matchEcho links echo requests and replies in the first pass and returns the
// stored link for the frame.
func matchEcho(p *d.Proto, pi *d.PacketInfo, id, seq uint16, v6, reply bool) *echoLink {
	sess := pi.Sess
	if !pi.Visited && !pi.InErrorPkt {
		st, _ := sess.ProtoState(p).(*echoState)
		if st == nil {
			st = &echoState{pending: map[echoKey]echoReq{}}
			sess.SetProtoState(p, st)
		}
		k := echoKeyOf(pi, id, seq, v6, reply)
		if !reply {
			st.pending[k] = echoReq{pi.Num, pi.TS}
		} else if req, ok := st.pending[k]; ok {
			delete(st.pending, k)
			rt := float64(pi.TS-req.ts) / 1e6
			sess.SetFrameData(p, pi.Num, 0, &echoLink{peer: req.frame, isReply: true, respTime: rt})
			sess.SetFrameData(p, req.frame, 0, &echoLink{peer: pi.Num})
		}
	}
	l, _ := sess.FrameData(p, pi.Num, 0).(*echoLink)
	return l
}

func icmpCodeName(typ, code uint64) string {
	var m map[uint64]string
	switch typ {
	case 3:
		m = icmpUnreachCodes
	case 5:
		m = icmpRedirectCodes
	case 11:
		m = icmpTTLCodes
	case 12:
		m = icmpParamCodes
	}
	if m != nil {
		if s, ok := m[code]; ok {
			return s
		}
	}
	return ""
}

func dissectICMP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	typ, code := uint64(tvb.U8(0)), uint64(tvb.U8(1))
	it := tree.AddProtocol(protoICMP, tvb, 0, -1)
	if !pi.InErrorPkt {
		pi.SetProtocol("ICMP")
	}
	it.AddUint(hfICMPType, tvb, 0, 1)
	cn, _ := it.AddUint(hfICMPCode, tvb, 1, 1)
	codeName := icmpCodeName(typ, code)
	if codeName != "" {
		cn.SetText("Code: %d (%s)", code, codeName)
	}
	ckn, _ := it.AddUint(hfICMPChecksum, tvb, 2, 2)
	if tvb.Len() == tvb.Reported() {
		if InetChecksum(tvb.Raw(), 0) == 0 {
			ckn.AppendText(" [correct]")
			it.AddGenerated(hfICMPCkStatus, d.Value{U: 1})
		} else {
			ckn.AppendText(" [incorrect]")
			it.AddGenerated(hfICMPCkStatus, d.Value{U: 0})
		}
	} else {
		it.AddGenerated(hfICMPCkStatus, d.Value{U: 2})
	}
	info := icmpTypes[typ]
	if info == "" {
		info = fmt.Sprintf("Unknown ICMP (obsolete or malformed?) type %d", typ)
	}
	if codeName != "" {
		info += " (" + codeName + ")"
	}

	switch typ {
	case 0, 8, 13, 14, 15, 16, 17, 18:
		id, seq := tvb.U16(4), tvb.U16(6)
		it.AddUint(hfICMPIdent, tvb, 4, 2)
		it.AddUintLE(hfICMPIdentLE, tvb, 4, 2)
		it.AddUint(hfICMPSeq, tvb, 6, 2)
		it.AddUintLE(hfICMPSeqLE, tvb, 6, 2)
		info += fmt.Sprintf("  id=0x%04x, seq=%d/%d", id, seq, seq>>8|seq<<8)
		if pi.NetSrc.Type == d.AddrIPv4 && !pi.InErrorPkt {
			if ip, ok := pi.Scratch(protoIP).(*IPInfo); ok {
				info += fmt.Sprintf(", ttl=%d", ip.TTL)
			}
		}
		if typ == 0 || typ == 8 {
			link := matchEcho(protoICMP, pi, id, seq, false, typ == 0)
			addEchoLinks(it, pi, link, typ == 0, hfICMPRespIn, hfICMPRespTo, hfICMPRespTime, hfICMPNoResp, eiICMPNoResp, &info)
		}
		switch typ {
		case 13, 14:
			it.AddUint(hfICMPTSOrig, tvb, 8, 4)
			it.AddUint(hfICMPTSRecv, tvb, 12, 4)
			it.AddUint(hfICMPTSXmit, tvb, 16, 4)
		default:
			if tvb.Remaining(8) > 0 {
				dt := it.AddText(tvb, 8, tvb.Remaining(8), "Data (%d bytes)", tvb.Remaining(8))
				dt.AddBytes(hfICMPData, tvb, 8, -1)
			}
		}
	case 3, 4, 5, 11, 12:
		switch {
		case typ == 3 && code == 4:
			it.AddBytes(hfICMPUnused, tvb, 4, 2)
			it.AddUint(hfICMPMTU, tvb, 6, 2)
		case typ == 5:
			it.AddIPv4(hfICMPGateway, tvb, 4)
		case typ == 12:
			it.AddUint(hfICMPPointer, tvb, 4, 1)
		default:
			it.AddBytes(hfICMPUnused, tvb, 4, 4)
		}
		if tvb.Remaining(8) > 0 {
			// The offending datagram: dissect without touching columns/state.
			saved := pi.InErrorPkt
			pi.InErrorPkt = true
			pi.Call(ipHandle, tvb.Sub(8, -1), it)
			pi.InErrorPkt = saved
		}
	default:
		if tvb.Remaining(4) > 0 {
			it.AddBytes(hfICMPData, tvb, 4, -1)
		}
	}
	if !pi.InErrorPkt {
		pi.SetInfo(info)
	}
	return tvb.Len()
}

func addEchoLinks(it *d.Node, pi *d.PacketInfo, link *echoLink, reply bool, hfIn, hfTo, hfTime, hfNo *d.FieldDef, ei *d.ExpertField, info *string) {
	switch {
	case link != nil && link.isReply:
		it.AddGenerated(hfTo, d.Value{U: uint64(link.peer)}).SetLink(link.peer)
		it.AddGenerated(hfTime, d.Value{F: link.respTime})
		*info += fmt.Sprintf(" (request in %d)", link.peer)
	case link != nil:
		it.AddGenerated(hfIn, d.Value{U: uint64(link.peer)}).SetLink(link.peer)
		*info += fmt.Sprintf(" (reply in %d)", link.peer)
	case !reply && pi.Visited:
		n := it.AddGenerated(hfNo, d.Value{})
		n.AddExpert(ei, "")
		*info += " (no response found!)"
	}
}
