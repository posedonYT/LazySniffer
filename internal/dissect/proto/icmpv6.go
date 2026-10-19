package proto

import (
	"fmt"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	icmpv6Types = map[uint64]string{1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
		4: "Parameter Problem", 128: "Echo (ping) request", 129: "Echo (ping) reply",
		130: "Multicast Listener Query", 131: "Multicast Listener Report", 132: "Multicast Listener Done",
		133: "Router Solicitation", 134: "Router Advertisement", 135: "Neighbor Solicitation",
		136: "Neighbor Advertisement", 137: "Redirect", 138: "Router Renumbering",
		143: "Multicast Listener Report Message v2", 155: "RPL Control"}
	icmpv6Unreach = map[uint64]string{0: "no route to destination", 1: "communication with destination administratively prohibited",
		2: "beyond scope of source address", 3: "address unreachable", 4: "port unreachable",
		5: "source address failed ingress/egress policy", 6: "reject route to destination"}
	icmpv6TimeEx = map[uint64]string{0: "hop limit exceeded in transit", 1: "fragment reassembly time exceeded"}
	ndOptTypes   = map[uint64]string{1: "Source link-layer address", 2: "Target link-layer address", 3: "Prefix information",
		4: "Redirected header", 5: "MTU", 14: "Nonce", 24: "Route Information", 25: "Recursive DNS Server",
		31: "DNS Search List", 38: "PREF64"}

	protoICMPv6      = d.RegisterProto("Internet Control Message Protocol v6", "ICMPv6", "icmpv6")
	hfICMPv6Type     = protoICMPv6.Field("icmpv6.type", "Type", d.FtUint8, d.WithVS(icmpv6Types))
	hfICMPv6Code     = protoICMPv6.Field("icmpv6.code", "Code", d.FtUint8)
	hfICMPv6Checksum = protoICMPv6.Field("icmpv6.checksum", "Checksum", d.FtUint16, d.WithBase(d.BaseHex))
	hfICMPv6CkStatus = protoICMPv6.Field("icmpv6.checksum.status", "Checksum Status", d.FtUint8, d.WithVS(checksumStatus), d.WithBase(d.BaseNone))
	hfICMPv6EchoID   = protoICMPv6.Field("icmpv6.echo.identifier", "Identifier", d.FtUint16, d.WithBase(d.BaseHex))
	hfICMPv6EchoSeq  = protoICMPv6.Field("icmpv6.echo.sequence_number", "Sequence", d.FtUint16)
	hfICMPv6RespIn   = protoICMPv6.Field("icmpv6.resp_in", "Response In", d.FtFrameNum)
	hfICMPv6RespTo   = protoICMPv6.Field("icmpv6.resp_to", "Response To", d.FtFrameNum)
	hfICMPv6RespTime = protoICMPv6.Field("icmpv6.resptime", "Response Time", d.FtDouble, d.WithUnit("ms"))
	hfICMPv6NoResp   = protoICMPv6.Field("icmpv6.no_resp", "No response seen", d.FtNone)
	hfICMPv6MTU      = protoICMPv6.Field("icmpv6.mtu", "MTU", d.FtUint32)
	hfICMPv6Reserved = protoICMPv6.Field("icmpv6.reserved", "Reserved", d.FtBytes)
	hfICMPv6Data     = protoICMPv6.Field("icmpv6.data", "Data", d.FtBytes)
	hfNDNSTarget     = protoICMPv6.Field("icmpv6.nd.ns.target_address", "Target Address", d.FtIPv6)
	hfNDNATarget     = protoICMPv6.Field("icmpv6.nd.na.target_address", "Target Address", d.FtIPv6)
	hfNDNAFlag       = protoICMPv6.Field("icmpv6.nd.na.flag", "Flags", d.FtUint32, d.WithBase(d.BaseHex))
	hfNDNAFlagR      = protoICMPv6.Field("icmpv6.nd.na.flag.r", "Router", d.FtBool, d.WithMask(0x80000000), d.WithParentBits(32), d.WithTFS(d.TFSSet))
	hfNDNAFlagS      = protoICMPv6.Field("icmpv6.nd.na.flag.s", "Solicited", d.FtBool, d.WithMask(0x40000000), d.WithParentBits(32), d.WithTFS(d.TFSSet))
	hfNDNAFlagO      = protoICMPv6.Field("icmpv6.nd.na.flag.o", "Override", d.FtBool, d.WithMask(0x20000000), d.WithParentBits(32), d.WithTFS(d.TFSSet))
	hfNDRAHop        = protoICMPv6.Field("icmpv6.nd.ra.cur_hop_limit", "Cur hop limit", d.FtUint8)
	hfNDRAFlag       = protoICMPv6.Field("icmpv6.nd.ra.flag", "Flags", d.FtUint8, d.WithBase(d.BaseHex))
	hfNDRALife       = protoICMPv6.Field("icmpv6.nd.ra.router_lifetime", "Router lifetime (s)", d.FtUint16)
	hfNDRAReach      = protoICMPv6.Field("icmpv6.nd.ra.reachable_time", "Reachable time (ms)", d.FtUint32)
	hfNDRARetrans    = protoICMPv6.Field("icmpv6.nd.ra.retrans_timer", "Retrans timer (ms)", d.FtUint32)
	hfNDRedirTarget  = protoICMPv6.Field("icmpv6.nd.rd.target_address", "Target Address", d.FtIPv6)
	hfNDRedirDest    = protoICMPv6.Field("icmpv6.nd.rd.destination_address", "Destination Address", d.FtIPv6)
	hfOptType6       = protoICMPv6.Field("icmpv6.opt.type", "Type", d.FtUint8, d.WithVS(ndOptTypes))
	hfOptLen6        = protoICMPv6.Field("icmpv6.opt.length", "Length", d.FtUint8)
	hfOptLinkAddr    = protoICMPv6.Field("icmpv6.opt.linkaddr", "Link-layer address", d.FtEther)
	hfOptSrcLinkAddr = protoICMPv6.Field("icmpv6.opt.src_linkaddr", "Source Link-layer address", d.FtEther)
	hfOptTgtLinkAddr = protoICMPv6.Field("icmpv6.opt.target_linkaddr", "Target Link-layer address", d.FtEther)
	hfOptPrefixLen   = protoICMPv6.Field("icmpv6.opt.prefix.length", "Prefix Length", d.FtUint8)
	hfOptPrefixValid = protoICMPv6.Field("icmpv6.opt.prefix.valid_lifetime", "Valid Lifetime", d.FtUint32)
	hfOptPrefixPref  = protoICMPv6.Field("icmpv6.opt.prefix.preferred_lifetime", "Preferred Lifetime", d.FtUint32)
	hfOptPrefix      = protoICMPv6.Field("icmpv6.opt.prefix", "Prefix", d.FtIPv6)
	hfOptMTU         = protoICMPv6.Field("icmpv6.opt.mtu", "MTU", d.FtUint32)
	hfOptRDNSS       = protoICMPv6.Field("icmpv6.opt.rdnss", "Recursive DNS Servers", d.FtIPv6)
	hfOptLifetime    = protoICMPv6.Field("icmpv6.opt.lifetime", "Lifetime", d.FtUint32)
	hfMLDMaxDelay    = protoICMPv6.Field("icmpv6.mld.maximum_response_delay", "Maximum Response Delay [ms]", d.FtUint16)
	hfMLDAddr        = protoICMPv6.Field("icmpv6.mld.multicast_address", "Multicast Address", d.FtIPv6)
	hfMLDRNum        = protoICMPv6.Field("icmpv6.mldr.nb_mcast_records", "Number of Multicast Address Records", d.FtUint16)
	hfMLDRType       = protoICMPv6.Field("icmpv6.mldr.mar.record_type", "Record Type", d.FtUint8, d.WithVS(igmpRecTypes))
	hfMLDRAux        = protoICMPv6.Field("icmpv6.mldr.mar.aux_data_len", "Aux Data Len", d.FtUint8)
	hfMLDRNSrc       = protoICMPv6.Field("icmpv6.mldr.mar.nb_sources", "Number of Sources", d.FtUint16)
	hfMLDRAddr       = protoICMPv6.Field("icmpv6.mldr.mar.multicast_address", "Multicast Address", d.FtIPv6)
	hfMLDRSrc        = protoICMPv6.Field("icmpv6.mldr.mar.source_address", "Source Address", d.FtIPv6)
	eiICMPv6NoResp   = protoICMPv6.Expert("icmpv6.resp_not_found", d.GroupSequence, d.SevWarn, "No response seen to ICMPv6 request")
)

func init() {
	IPProtoTable.Add(58, d.NewHandle(protoICMPv6, dissectICMPv6))
}

func dissectICMPv6(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	typ, code := uint64(tvb.U8(0)), uint64(tvb.U8(1))
	it := tree.AddProtocol(protoICMPv6, tvb, 0, -1)
	if !pi.InErrorPkt {
		pi.SetProtocol("ICMPv6")
	}
	it.AddUint(hfICMPv6Type, tvb, 0, 1)
	cn, _ := it.AddUint(hfICMPv6Code, tvb, 1, 1)
	ckn, _ := it.AddUint(hfICMPv6Checksum, tvb, 2, 2)
	verified := false
	if tvb.Len() == tvb.Reported() && pi.NetSrc.Type == d.AddrIPv6 && !pi.InErrorPkt {
		// Pseudo-header: src, dst, upper-layer length, next header 58.
		var sum uint32
		for _, a := range [][]byte{pi.NetSrc.Bytes(), pi.NetDst.Bytes()} {
			for i := 0; i < 16; i += 2 {
				sum += uint32(a[i])<<8 | uint32(a[i+1])
			}
		}
		sum += uint32(tvb.Len()) + 58
		if InetChecksum(tvb.Raw(), sum) == 0 {
			ckn.AppendText(" [correct]")
			it.AddGenerated(hfICMPv6CkStatus, d.Value{U: 1})
		} else {
			ckn.AppendText(" [incorrect]")
			it.AddGenerated(hfICMPv6CkStatus, d.Value{U: 0})
		}
		verified = true
	}
	if !verified {
		it.AddGenerated(hfICMPv6CkStatus, d.Value{U: 2})
	}
	info := icmpv6Types[typ]
	if info == "" {
		info = fmt.Sprintf("Unknown ICMPv6 type %d", typ)
	}
	switch typ {
	case 1:
		if s := icmpv6Unreach[code]; s != "" {
			cn.SetText("Code: %d (%s)", code, s)
			info += " (" + s + ")"
		}
	case 3:
		if s := icmpv6TimeEx[code]; s != "" {
			cn.SetText("Code: %d (%s)", code, s)
			info += " (" + s + ")"
		}
	}

	switch typ {
	case 1, 2, 3, 4:
		if typ == 2 {
			it.AddUint(hfICMPv6MTU, tvb, 4, 4)
		} else {
			it.AddBytes(hfICMPv6Reserved, tvb, 4, 4)
		}
		if tvb.Remaining(8) > 0 {
			saved := pi.InErrorPkt
			pi.InErrorPkt = true
			pi.Call(ipv6Handle, tvb.Sub(8, -1), it)
			pi.InErrorPkt = saved
		}
	case 128, 129:
		_, id := it.AddUint(hfICMPv6EchoID, tvb, 4, 2)
		_, seq := it.AddUint(hfICMPv6EchoSeq, tvb, 6, 2)
		info += fmt.Sprintf(" id=0x%04x, seq=%d", id, seq)
		if pi.NetSrc.Type == d.AddrIPv6 && !pi.InErrorPkt {
			if ip, ok := pi.Scratch(protoIP).(*IPInfo); ok {
				info += fmt.Sprintf(", hop limit=%d", ip.TTL)
			}
		}
		link := matchEcho(protoICMPv6, pi, uint16(id), uint16(seq), true, typ == 129)
		addEchoLinks(it, pi, link, typ == 129, hfICMPv6RespIn, hfICMPv6RespTo, hfICMPv6RespTime, hfICMPv6NoResp, eiICMPv6NoResp, &info)
		if tvb.Remaining(8) > 0 {
			it.AddBytes(hfICMPv6Data, tvb, 8, -1)
		}
	case 130, 131, 132:
		it.AddUint(hfMLDMaxDelay, tvb, 4, 2)
		it.AddBytes(hfICMPv6Reserved, tvb, 6, 2)
		if tvb.Has(8, 16) {
			_, a := it.AddBytes(hfMLDAddr, tvb, 8, 16)
			if typ != 130 || !isZero(a) {
				info += " " + d.FormatIPv6(a)
			}
		}
	case 143:
		it.AddBytes(hfICMPv6Reserved, tvb, 4, 2)
		_, n := it.AddUint(hfMLDRNum, tvb, 6, 2)
		off := 8
		for i := 0; i < int(n); i++ {
			rt := uint64(tvb.U8(off))
			aux := int(tvb.U8(off+1)) * 4
			ns := int(tvb.U16(off + 2))
			a := tvb.Bytes(off+4, 16)
			rn := it.AddText(tvb, off, 20+16*ns+aux, "Multicast Address Record %s: %s", d.FormatIPv6(a), igmpRecTypes[rt])
			rn.AddUint(hfMLDRType, tvb, off, 1)
			rn.AddUint(hfMLDRAux, tvb, off+1, 1)
			rn.AddUint(hfMLDRNSrc, tvb, off+2, 2)
			rn.AddBytes(hfMLDRAddr, tvb, off+4, 16)
			for s := 0; s < ns; s++ {
				rn.AddBytes(hfMLDRSrc, tvb, off+20+16*s, 16)
			}
			off += 20 + 16*ns + aux
		}
	case 133:
		it.AddBytes(hfICMPv6Reserved, tvb, 4, 4)
		if mac := dissectNDOpts(it, tvb, 8); mac != "" {
			info += " from " + mac
		}
	case 134:
		it.AddUint(hfNDRAHop, tvb, 4, 1)
		it.AddUint(hfNDRAFlag, tvb, 5, 1)
		it.AddUint(hfNDRALife, tvb, 6, 2)
		it.AddUint(hfNDRAReach, tvb, 8, 4)
		it.AddUint(hfNDRARetrans, tvb, 12, 4)
		if mac := dissectNDOpts(it, tvb, 16); mac != "" {
			info += " from " + mac
		}
	case 135:
		it.AddBytes(hfICMPv6Reserved, tvb, 4, 4)
		_, tgt := it.AddBytes(hfNDNSTarget, tvb, 8, 16)
		info += " for " + d.FormatIPv6(tgt)
		if mac := dissectNDOpts(it, tvb, 24); mac != "" {
			info += " from " + mac
		}
	case 136:
		fl := tvb.U32(4)
		fn := it.AddUintValue(hfNDNAFlag, tvb, 4, 4, uint64(fl))
		fn.AddBits(hfNDNAFlagR, tvb, 4, 4, uint64(fl))
		fn.AddBits(hfNDNAFlagS, tvb, 4, 4, uint64(fl))
		fn.AddBits(hfNDNAFlagO, tvb, 4, 4, uint64(fl))
		_, tgt := it.AddBytes(hfNDNATarget, tvb, 8, 16)
		var flags []string
		if fl&0x80000000 != 0 {
			flags = append(flags, "rtr")
		}
		if fl&0x40000000 != 0 {
			flags = append(flags, "sol")
		}
		if fl&0x20000000 != 0 {
			flags = append(flags, "ovr")
		}
		info += " " + d.FormatIPv6(tgt)
		if len(flags) > 0 {
			info += " (" + joinComma(flags) + ")"
		}
		if mac := dissectNDOpts(it, tvb, 24); mac != "" {
			info += " is at " + mac
		}
	case 137:
		it.AddBytes(hfICMPv6Reserved, tvb, 4, 4)
		it.AddBytes(hfNDRedirTarget, tvb, 8, 16)
		it.AddBytes(hfNDRedirDest, tvb, 24, 16)
		dissectNDOpts(it, tvb, 40)
	default:
		if tvb.Remaining(4) > 0 {
			it.AddBytes(hfICMPv6Data, tvb, 4, -1)
		}
	}
	if !pi.InErrorPkt {
		pi.SetInfo(info)
	}
	return tvb.Len()
}

func joinComma(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

// dissectNDOpts parses Neighbor Discovery options; it returns a link-layer
// address found in a source/target option for the Info column.
func dissectNDOpts(it *d.Node, tvb *d.Tvb, off int) string {
	mac := ""
	for tvb.Remaining(off) >= 2 {
		typ := uint64(tvb.U8(off))
		l := int(tvb.U8(off+1)) * 8
		if l == 0 || !tvb.Has(off, l) {
			break
		}
		name := ndOptTypes[typ]
		if name == "" {
			name = fmt.Sprintf("Unknown (%d)", typ)
		}
		on := it.AddText(tvb, off, l, "ICMPv6 Option (%s)", name)
		on.AddUint(hfOptType6, tvb, off, 1)
		ln, _ := on.AddUint(hfOptLen6, tvb, off+1, 1)
		ln.AppendText(" (%d bytes)", l)
		switch typ {
		case 1, 2:
			if l >= 8 {
				on.AddBytes(hfOptLinkAddr, tvb, off+2, 6)
				hf := hfOptSrcLinkAddr
				if typ == 2 {
					hf = hfOptTgtLinkAddr
				}
				_, b := on.AddBytes(hf, tvb, off+2, 6)
				mac = resolveEther(b)
				on.AppendText(" : %s", mac)
			}
		case 3:
			if l >= 32 {
				on.AddUint(hfOptPrefixLen, tvb, off+2, 1)
				on.AddUint(hfOptPrefixValid, tvb, off+4, 4)
				on.AddUint(hfOptPrefixPref, tvb, off+8, 4)
				_, p := on.AddBytes(hfOptPrefix, tvb, off+16, 16)
				on.AppendText(" : %s/%d", d.FormatIPv6(p), tvb.U8(off+2))
			}
		case 5:
			if l >= 8 {
				_, mtu := on.AddUint(hfOptMTU, tvb, off+4, 4)
				on.AppendText(" : %d", mtu)
			}
		case 25:
			if l >= 24 {
				on.AddUint(hfOptLifetime, tvb, off+4, 4)
				for p := off + 8; p+16 <= off+l; p += 16 {
					on.AddBytes(hfOptRDNSS, tvb, p, 16)
				}
			}
		}
		off += l
	}
	return mac
}
