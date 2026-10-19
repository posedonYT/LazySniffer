package proto

import (
	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	protoIPv6     = d.RegisterProto("Internet Protocol Version 6", "IPv6", "ipv6")
	hfIPv6Version = protoIPv6.Field("ipv6.version", "Version", d.FtUint32, d.WithMask(0xf0000000))
	hfIPv6TClass  = protoIPv6.Field("ipv6.tclass", "Traffic Class", d.FtUint32, d.WithMask(0x0ff00000), d.WithBase(d.BaseHex))
	hfIPv6DSCP    = protoIPv6.Field("ipv6.tclass.dscp", "Differentiated Services Codepoint", d.FtUint32, d.WithMask(0x0fc00000), d.WithVS(dscpNames))
	hfIPv6ECN     = protoIPv6.Field("ipv6.tclass.ecn", "Explicit Congestion Notification", d.FtUint32, d.WithMask(0x00300000), d.WithVS(ecnNames))
	hfIPv6Flow    = protoIPv6.Field("ipv6.flow", "Flow Label", d.FtUint32, d.WithMask(0x000fffff), d.WithBase(d.BaseHex))
	hfIPv6Plen    = protoIPv6.Field("ipv6.plen", "Payload Length", d.FtUint16)
	hfIPv6Nxt     = protoIPv6.Field("ipv6.nxt", "Next Header", d.FtUint8, d.WithVS(IPProtos))
	hfIPv6Hlim    = protoIPv6.Field("ipv6.hlim", "Hop Limit", d.FtUint8)
	hfIPv6Src     = protoIPv6.Field("ipv6.src", "Source Address", d.FtIPv6)
	hfIPv6Dst     = protoIPv6.Field("ipv6.dst", "Destination Address", d.FtIPv6)
	hfIPv6Addr    = protoIPv6.Field("ipv6.addr", "Source or Destination Address", d.FtIPv6)
	hfIPv6SrcHost = protoIPv6.Field("ipv6.src_host", "Source Host", d.FtString)
	hfIPv6DstHost = protoIPv6.Field("ipv6.dst_host", "Destination Host", d.FtString)
	hfIPv6Host    = protoIPv6.Field("ipv6.host", "Source or Destination Host", d.FtString)
	eiIPv6BadVer  = protoIPv6.Expert("ipv6.bogus_ipv6_version", d.GroupMalformed, d.SevError, "Bogus IP version")

	protoHopOpts  = d.RegisterProto("IPv6 Hop-by-Hop Option", "IPv6 Hop-by-Hop", "ipv6.hopopts")
	protoDstOpts  = d.RegisterProto("Destination Options for IPv6", "IPv6 Destination", "ipv6.dstopts")
	protoRouting  = d.RegisterProto("Routing Header for IPv6", "IPv6 Routing", "ipv6.routing")
	protoFragment = d.RegisterProto("Fragment Header for IPv6", "IPv6 Fragment", "ipv6.fraghdr")

	hfHopNxt  = protoHopOpts.Field("ipv6.hopopts.nxt", "Next Header", d.FtUint8, d.WithVS(IPProtos))
	hfHopLen  = protoHopOpts.Field("ipv6.hopopts.len", "Length", d.FtUint8)
	hfDstNxt  = protoDstOpts.Field("ipv6.dstopts.nxt", "Next Header", d.FtUint8, d.WithVS(IPProtos))
	hfDstLen  = protoDstOpts.Field("ipv6.dstopts.len", "Length", d.FtUint8)
	hfOptType = protoIPv6.Field("ipv6.opt.type", "Type", d.FtUint8, d.WithBase(d.BaseHex),
		d.WithVS(map[uint64]string{0: "Pad1", 1: "PadN", 5: "Router Alert", 0xc2: "Jumbo Payload", 0x63: "RPL Option", 0x26: "Quick-Start"}))
	hfOptLen     = protoIPv6.Field("ipv6.opt.length", "Length", d.FtUint8)
	hfRoutNxt    = protoRouting.Field("ipv6.routing.nxt", "Next Header", d.FtUint8, d.WithVS(IPProtos))
	hfRoutLen    = protoRouting.Field("ipv6.routing.len", "Length", d.FtUint8)
	hfRoutType   = protoRouting.Field("ipv6.routing.type", "Type", d.FtUint8, d.WithVS(map[uint64]string{0: "Source Route", 2: "Type 2 Routing", 3: "RPL Source Route", 4: "Segment Routing"}))
	hfRoutSegs   = protoRouting.Field("ipv6.routing.segleft", "Segments Left", d.FtUint8)
	hfFragNxt    = protoFragment.Field("ipv6.fraghdr.nxt", "Next header", d.FtUint8, d.WithVS(IPProtos))
	hfFragOffset = protoFragment.Field("ipv6.fraghdr.offset", "Offset", d.FtUint16, d.WithMask(0xfff8))
	hfFragMore   = protoFragment.Field("ipv6.fraghdr.more", "More Fragments", d.FtBool, d.WithMask(0x0001), d.WithParentBits(16), d.WithTFS(d.TFSYesNo))
	hfFragID     = protoFragment.Field("ipv6.fraghdr.ident", "Identification", d.FtUint32, d.WithBase(d.BaseHex))

	ipv6Handle = d.RegisterHandle("ipv6", d.NewHandle(protoIPv6, dissectIPv6))
)

func init() {
	EtherTypeTable.Add(0x86dd, ipv6Handle)
	IPProtoTable.Add(41, ipv6Handle)
}

func dissectIPv6(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	w := tvb.U32(0)
	it := tree.AddProtocol(protoIPv6, tvb, 0, 40)
	if !pi.InErrorPkt {
		pi.SetProtocol("IPv6")
	}
	vn := it.AddBits(hfIPv6Version, tvb, 0, 1, uint64(w))
	if w>>28 != 6 {
		vn.AddExpert(eiIPv6BadVer, "Bogus IPv6 version (%d, must be 6)", w>>28)
		return tvb.Len()
	}
	it.AddHidden(hfIPVersion, tvb, 0, 1, d.UintValue(d.FtUint8, 6)) // like Wireshark: ip.version is 6 for IPv6 too
	tc := uint64(w>>20) & 0xff
	tcn := it.AddBits(hfIPv6TClass, tvb, 0, 4, uint64(w))
	tcn.SetText("%s = Traffic Class: 0x%02x (DSCP: %s, ECN: %s)", hfIPv6TClass.BitPattern(uint64(w)), tc, dscpShortName(tc>>2), ecnShort[tc&3])
	tcn.AddBits(hfIPv6DSCP, tvb, 0, 4, uint64(w))
	tcn.AddBits(hfIPv6ECN, tvb, 0, 4, uint64(w))
	it.AddBits(hfIPv6Flow, tvb, 1, 3, uint64(w))
	_, plen := it.AddUint(hfIPv6Plen, tvb, 4, 2)
	_, nxt := it.AddUint(hfIPv6Nxt, tvb, 6, 1)
	_, hlim := it.AddUint(hfIPv6Hlim, tvb, 7, 1)
	if !pi.InErrorPkt {
		pi.SetScratch(protoIP, &IPInfo{TTL: uint8(hlim)})
	}
	_, src := it.AddBytes(hfIPv6Src, tvb, 8, 16)
	_, dst := it.AddBytes(hfIPv6Dst, tvb, 24, 16)
	it.AddHidden(hfIPv6Addr, tvb, 8, 16, d.Value{B: src})
	it.AddHidden(hfIPv6Addr, tvb, 24, 16, d.Value{B: dst})
	srcA, dstA := d.IPv6Addr(src), d.IPv6Addr(dst)
	if it.Tree().Wants(hfIPv6Host) || it.Tree().Wants(hfIPv6SrcHost) || it.Tree().Wants(hfIPv6DstHost) {
		sh, dh := hostName(srcA), hostName(dstA)
		it.AddHidden(hfIPv6SrcHost, tvb, 8, 16, d.StringValue(sh))
		it.AddHidden(hfIPv6DstHost, tvb, 24, 16, d.StringValue(dh))
		it.AddHidden(hfIPv6Host, tvb, 8, 16, d.StringValue(sh))
		it.AddHidden(hfIPv6Host, tvb, 24, 16, d.StringValue(dh))
	}
	it.SetText("Internet Protocol Version 6, Src: %s, Dst: %s", srcA, dstA)
	if !pi.InErrorPkt {
		pi.SetNetAddrs(srcA, dstA)
	}
	total := 40 + int(plen)
	if plen == 0 {
		total = tvb.Reported() // jumbogram or TSO
	}
	reported := min(total, tvb.Reported())
	body := tvb.Sub(0, reported)
	off := 40

	// Walk extension headers.
	for {
		switch nxt {
		case 0, 60:
			p, hfN, hfL := protoHopOpts, hfHopNxt, hfHopLen
			if nxt == 60 {
				p, hfN, hfL = protoDstOpts, hfDstNxt, hfDstLen
			}
			l := (int(body.U8(off+1)) + 1) * 8
			et := tree.AddProtocol(p, body, off, l)
			_, n := et.AddUint(hfN, body, off, 1)
			ln, _ := et.AddUint(hfL, body, off+1, 1)
			ln.AppendText(" [%d bytes]", l)
			dissectIPv6Opts(et, body, off+2, off+l)
			nxt = n
			off += l
			continue
		case 43:
			l := (int(body.U8(off+1)) + 1) * 8
			rt := tree.AddProtocol(protoRouting, body, off, l)
			_, n := rt.AddUint(hfRoutNxt, body, off, 1)
			rt.AddUint(hfRoutLen, body, off+1, 1)
			_, typ := rt.AddUint(hfRoutType, body, off+2, 1)
			rt.AddUint(hfRoutSegs, body, off+3, 1)
			rt.SetText("Routing Header for IPv6 (%s)", hfRoutType.VS[typ])
			nxt = n
			off += l
			continue
		case 44:
			ft := tree.AddProtocol(protoFragment, body, off, 8)
			_, n := ft.AddUint(hfFragNxt, body, off, 1)
			fo := body.U16(off + 2)
			ft.AddBits(hfFragOffset, body, off+2, 2, uint64(fo))
			ft.AddBits(hfFragMore, body, off+2, 2, uint64(fo))
			_, id := ft.AddUint(hfFragID, body, off+4, 4)
			offset := int(fo>>3) * 8
			off += 8
			more := fo&1 != 0
			if offset != 0 || more {
				if IPDefragment && !pi.InErrorPkt {
					key := ipFragKey{id: uint32(id), proto: uint8(n)}
					copy(key.src[:], src)
					copy(key.dst[:], dst)
					r, in := defragment(pi, protoIPv6, &ipv6FragFields, key, body.Sub(off, -1), offset, more, tree)
					if r == nil {
						pi.SetInfof("IPv6 fragment (off=%d more=%s ident=0x%08x nxt=%d)", offset, yn(more), id, n)
						if in != 0 {
							pi.AppendInfo(" [Reassembled in #%d]", in)
						}
						pi.Call(DataHandle, body.Sub(off, -1), tree)
						return reported
					}
					dispatchIPv6Payload(n, r, pi, tree)
					return reported
				}
				pi.SetInfof("IPv6 fragment (off=%d more=%s ident=0x%08x nxt=%d)", offset, yn(more), id, n)
				if offset != 0 {
					pi.Call(DataHandle, body.Sub(off, -1), tree)
					return reported
				}
			}
			nxt = n
			continue
		case 59:
			if body.Remaining(off) > 0 {
				pi.Call(DataHandle, body.Sub(off, -1), tree)
			}
			return reported
		}
		break
	}
	payload := body.Sub(off, -1)
	if pi.InErrorPkt && payload.Len() == 0 {
		return reported
	}
	dispatchIPv6Payload(nxt, payload, pi, tree)
	return reported
}

func dispatchIPv6Payload(nxt uint64, payload *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if _, ok := IPProtoTable.Try(nxt, payload, pi, tree); !ok {
		if !pi.InErrorPkt {
			pi.SetInfof("%s (%d)", ipProtoName(nxt), nxt)
		}
		pi.Call(DataHandle, payload, tree)
	}
	return payload.Len()
}

func yn(b bool) string {
	if b {
		return "y"
	}
	return "n"
}

func dissectIPv6Opts(et *d.Node, tvb *d.Tvb, off, end int) {
	for off < end {
		typ := tvb.U8(off)
		if typ == 0 {
			n := et.AddText(tvb, off, 1, "Pad1")
			n.AddUint(hfOptType, tvb, off, 1)
			off++
			continue
		}
		l := int(tvb.U8(off + 1))
		name := hfOptType.VS[uint64(typ)]
		if name == "" {
			name = "Unknown"
		}
		n := et.AddText(tvb, off, 2+l, "%s", name)
		n.AddUint(hfOptType, tvb, off, 1)
		n.AddUint(hfOptLen, tvb, off+1, 1)
		off += 2 + l
	}
}
