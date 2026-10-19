package proto

import (
	d "github.com/poseydon/lazysniffer/internal/dissect"
)

// IPProtos names IP protocol numbers.
var IPProtos = map[uint64]string{
	0: "IPv6 Hop-by-Hop Option", 1: "ICMP", 2: "IGMP", 4: "IPIP", 6: "TCP", 8: "EGP", 9: "IGP",
	17: "UDP", 27: "RDP", 33: "DCCP", 41: "IPv6", 43: "IPv6 Routing", 44: "IPv6 Fragment",
	46: "RSVP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 59: "IPv6 No Next Header",
	60: "IPv6 Destination Options", 88: "EIGRP", 89: "OSPF IGP", 97: "Ethernet-within-IP",
	103: "PIM", 112: "VRRP", 115: "L2TP", 132: "SCTP", 135: "Mobility Header", 136: "UDPLite",
	137: "MPLS in IP", 143: "Ethernet", 253: "Experimental", 254: "Experimental",
}

var (
	dscpNames = map[uint64]string{0: "Default", 1: "Lower Effort", 8: "Class Selector 1", 10: "Assured Forwarding 11",
		12: "Assured Forwarding 12", 14: "Assured Forwarding 13", 16: "Class Selector 2", 18: "Assured Forwarding 21",
		20: "Assured Forwarding 22", 22: "Assured Forwarding 23", 24: "Class Selector 3", 26: "Assured Forwarding 31",
		28: "Assured Forwarding 32", 30: "Assured Forwarding 33", 32: "Class Selector 4", 34: "Assured Forwarding 41",
		36: "Assured Forwarding 42", 38: "Assured Forwarding 43", 40: "Class Selector 5", 44: "Voice Admit",
		46: "Expedited Forwarding", 48: "Class Selector 6", 56: "Class Selector 7"}
	dscpShort = map[uint64]string{0: "CS0", 1: "LE", 8: "CS1", 10: "AF11", 12: "AF12", 14: "AF13", 16: "CS2",
		18: "AF21", 20: "AF22", 22: "AF23", 24: "CS3", 26: "AF31", 28: "AF32", 30: "AF33", 32: "CS4",
		34: "AF41", 36: "AF42", 38: "AF43", 40: "CS5", 44: "VA", 46: "EF", 48: "CS6", 56: "CS7"}
	ecnNames = map[uint64]string{0: "Not ECN-Capable Transport", 1: "ECN-Capable Transport codepoint '01'",
		2: "ECN-Capable Transport codepoint '10'", 3: "Congestion Experienced"}
	ecnShort       = map[uint64]string{0: "Not-ECT", 1: "ECT(1)", 2: "ECT(0)", 3: "CE"}
	checksumStatus = map[uint64]string{0: "Bad", 1: "Good", 2: "Unverified", 3: "Not present", 4: "Illegal"}

	protoIP       = d.RegisterProto("Internet Protocol Version 4", "IPv4", "ip")
	hfIPVersion   = protoIP.Field("ip.version", "Version", d.FtUint8, d.WithMask(0xf0))
	hfIPHdrLen    = protoIP.Field("ip.hdr_len", "Header Length", d.FtUint8, d.WithMask(0x0f))
	hfIPDS        = protoIP.Field("ip.dsfield", "Differentiated Services Field", d.FtUint8, d.WithBase(d.BaseHex))
	hfIPDSCP      = protoIP.Field("ip.dsfield.dscp", "Differentiated Services Codepoint", d.FtUint8, d.WithMask(0xfc), d.WithVS(dscpNames))
	hfIPECN       = protoIP.Field("ip.dsfield.ecn", "Explicit Congestion Notification", d.FtUint8, d.WithMask(0x03), d.WithVS(ecnNames))
	hfIPLen       = protoIP.Field("ip.len", "Total Length", d.FtUint16)
	hfIPID        = protoIP.Field("ip.id", "Identification", d.FtUint16, d.WithBase(d.BaseHexDec))
	hfIPFlags     = protoIP.Field("ip.flags", "Flags", d.FtUint8, d.WithBase(d.BaseHex))
	hfIPFlagRB    = protoIP.Field("ip.flags.rb", "Reserved bit", d.FtBool, d.WithMask(0x8000), d.WithParentBits(16), d.WithTFS(d.TFSSet))
	hfIPFlagDF    = protoIP.Field("ip.flags.df", "Don't fragment", d.FtBool, d.WithMask(0x4000), d.WithParentBits(16), d.WithTFS(d.TFSSet))
	hfIPFlagMF    = protoIP.Field("ip.flags.mf", "More fragments", d.FtBool, d.WithMask(0x2000), d.WithParentBits(16), d.WithTFS(d.TFSSet))
	hfIPFragOff   = protoIP.Field("ip.frag_offset", "Fragment Offset", d.FtUint16, d.WithMask(0x1fff))
	hfIPTTL       = protoIP.Field("ip.ttl", "Time to Live", d.FtUint8)
	hfIPProto     = protoIP.Field("ip.proto", "Protocol", d.FtUint8, d.WithVS(IPProtos))
	hfIPChecksum  = protoIP.Field("ip.checksum", "Header Checksum", d.FtUint16, d.WithBase(d.BaseHex))
	hfIPCkStatus  = protoIP.Field("ip.checksum.status", "Header checksum status", d.FtUint8, d.WithVS(checksumStatus), d.WithBase(d.BaseNone))
	hfIPCkCalc    = protoIP.Field("ip.checksum_calculated", "Calculated Checksum", d.FtUint16, d.WithBase(d.BaseHex))
	hfIPSrc       = protoIP.Field("ip.src", "Source Address", d.FtIPv4)
	hfIPDst       = protoIP.Field("ip.dst", "Destination Address", d.FtIPv4)
	hfIPAddr      = protoIP.Field("ip.addr", "Source or Destination Address", d.FtIPv4)
	hfIPSrcHost   = protoIP.Field("ip.src_host", "Source Host", d.FtString)
	hfIPDstHost   = protoIP.Field("ip.dst_host", "Destination Host", d.FtString)
	hfIPHost      = protoIP.Field("ip.host", "Source or Destination Host", d.FtString)
	hfIPOpts      = protoIP.Field("ip.options", "Options", d.FtBytes)
	hfIPOptType   = protoIP.Field("ip.opt.type", "Type", d.FtUint8)
	hfIPOptLen    = protoIP.Field("ip.opt.len", "Length", d.FtUint8)
	hfIPOptRA     = protoIP.Field("ip.opt.ra", "Router Alert", d.FtUint16, d.WithVS(map[uint64]string{0: "Router shall examine packet"}))
	eiIPBadHdrLen = protoIP.Expert("ip.bogus_header_length", d.GroupProtocol, d.SevError, "Bogus IP header length")
	eiIPBadLen    = protoIP.Expert("ip.bogus_ip_length", d.GroupProtocol, d.SevError, "Bogus IP length")
	eiIPBadVer    = protoIP.Expert("ip.bogus_ip_version", d.GroupProtocol, d.SevError, "Bogus IP version")
	eiIPTTLZero   = protoIP.Expert("ip.ttl.zero", d.GroupSequence, d.SevNote, "Time To Live is zero")
	eiIPBadCk     = protoIP.Expert("ip.checksum_bad.expert", d.GroupChecksum, d.SevError, "Bad checksum")
	eiIPTSO       = protoIP.Expert("ip.len.tso", d.GroupProtocol, d.SevNote, "Total Length reported as 0, presumed to be because of \"TCP segmentation offload\" (TSO)")

	// IPProtoTable dispatches IPv4 and IPv6 payloads by protocol number.
	IPProtoTable = d.Table("ip.proto")
	ipHandle     = d.RegisterHandle("ip", d.NewHandle(protoIP, dissectIP))

	// CheckIPChecksum enables header checksum validation (ip.check_checksum).
	CheckIPChecksum = false
	// HostResolver, when set, maps an address to a host name for *_host fields.
	HostResolver func(d.Address) string
)

// IPInfo is per-packet IPv4 header data for upper layers.
type IPInfo struct{ TTL uint8 }

func init() {
	EtherTypeTable.Add(0x0800, ipHandle)
	IPProtoTable.Add(4, ipHandle)
}

// InetChecksum computes the Internet one's-complement sum of b plus an
// initial partial sum.
func InetChecksum(b []byte, sum uint32) uint16 {
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func hostName(a d.Address) string {
	if HostResolver != nil {
		if s := HostResolver(a); s != "" {
			return s
		}
	}
	return a.String()
}

func dissectIP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	vhl := tvb.U8(0)
	hlen := int(vhl&0x0f) * 4
	it := tree.AddProtocol(protoIP, tvb, 0, max(hlen, 1))
	if !pi.InErrorPkt {
		pi.SetProtocol("IPv4")
	}
	vn, _ := it.AddUint(hfIPVersion, tvb, 0, 1)
	if vhl>>4 != 4 {
		vn.AddExpert(eiIPBadVer, "Bogus IP version (%d, must be 4)", vhl>>4)
		pi.SetInfof("Bogus IPv4 version (%d, must be 4)", vhl>>4)
		return tvb.Len()
	}
	hn := it.AddUintValue(hfIPHdrLen, tvb, 0, 1, uint64(hlen))
	hn.SetText("%s = Header Length: %d bytes (%d)", hfIPHdrLen.BitPattern(uint64(vhl)), hlen, vhl&0x0f)
	if hlen < 20 {
		hn.AddExpert(eiIPBadHdrLen, "Bogus IP header length (%d, must be at least 20)", hlen)
		pi.SetInfof("Bogus IP header length (%d, must be at least 20)", hlen)
		return tvb.Len()
	}
	tos := tvb.U8(1)
	dsn, _ := it.AddUint(hfIPDS, tvb, 1, 1)
	dsn.SetText("Differentiated Services Field: 0x%02x (DSCP: %s, ECN: %s)", tos, dscpShortName(uint64(tos>>2)), ecnShort[uint64(tos&3)])
	dsn.AddBits(hfIPDSCP, tvb, 1, 1, uint64(tos))
	dsn.AddBits(hfIPECN, tvb, 1, 1, uint64(tos))

	totalLen := int(tvb.U16(2))
	ln, _ := it.AddUint(hfIPLen, tvb, 2, 2)
	if totalLen == 0 {
		// TSO: the NIC fills the length in later.
		totalLen = tvb.Reported()
		ln.AddExpert(eiIPTSO, "")
	} else if totalLen < hlen {
		ln.AddExpert(eiIPBadLen, "Bogus IP length (%d, less than header length %d)", totalLen, hlen)
		pi.SetInfof("Bogus IP length (%d, less than header length %d)", totalLen, hlen)
		return tvb.Len()
	}
	_, id := it.AddUint(hfIPID, tvb, 4, 2)
	off := tvb.U16(6)
	flags := off >> 13
	fn := it.AddUintValue(hfIPFlags, tvb, 6, 1, uint64(flags))
	flagText := ""
	switch {
	case flags&2 != 0:
		flagText = ", Don't fragment"
	case flags&1 != 0:
		flagText = ", More fragments"
	}
	fn.SetText("%s = Flags: 0x%x%s", bitsPrefix(uint64(off), 0xe000, 16), flags, flagText)
	fn.AddBits(hfIPFlagRB, tvb, 6, 2, uint64(off))
	fn.AddBits(hfIPFlagDF, tvb, 6, 2, uint64(off))
	fn.AddBits(hfIPFlagMF, tvb, 6, 2, uint64(off))
	fragOff := int(off&0x1fff) * 8
	fo := it.AddBits(hfIPFragOff, tvb, 6, 2, uint64(off))
	fo.SetText("%s = Fragment Offset: %d", hfIPFragOff.BitPattern(uint64(off)), fragOff)
	_, ttl := it.AddUint(hfIPTTL, tvb, 8, 1)
	if !pi.InErrorPkt {
		pi.SetScratch(protoIP, &IPInfo{TTL: uint8(ttl)})
	}
	_, proto := it.AddUint(hfIPProto, tvb, 9, 1)
	ckn, ck := it.AddUint(hfIPChecksum, tvb, 10, 2)
	if CheckIPChecksum && tvb.Has(0, hlen) {
		calc := InetChecksum(tvb.Bytes(0, hlen), 0)
		if calc == 0 {
			ckn.AppendText(" [correct]")
			it.AddGenerated(hfIPCkStatus, d.Value{U: 1})
		} else {
			ckn.AppendText(" [incorrect, should be 0x%04x]", uint16(ck)+calc)
			ckn.AddExpert(eiIPBadCk, "")
			it.AddGenerated(hfIPCkStatus, d.Value{U: 0})
		}
	} else {
		it.AddGenerated(hfIPCkStatus, d.Value{U: 2})
	}
	sn, src := it.AddIPv4(hfIPSrc, tvb, 12)
	dn, dst := it.AddIPv4(hfIPDst, tvb, 16)
	_ = sn
	_ = dn
	srcA, dstA := d.IPv4Addr(src), d.IPv4Addr(dst)
	it.AddHidden(hfIPAddr, tvb, 12, 4, d.Value{U: uint64(src)})
	it.AddHidden(hfIPAddr, tvb, 16, 4, d.Value{U: uint64(dst)})
	if it.Tree().Wants(hfIPHost) || it.Tree().Wants(hfIPSrcHost) || it.Tree().Wants(hfIPDstHost) {
		sh, dh := hostName(srcA), hostName(dstA)
		it.AddHidden(hfIPSrcHost, tvb, 12, 4, d.StringValue(sh))
		it.AddHidden(hfIPDstHost, tvb, 16, 4, d.StringValue(dh))
		it.AddHidden(hfIPHost, tvb, 12, 4, d.StringValue(sh))
		it.AddHidden(hfIPHost, tvb, 16, 4, d.StringValue(dh))
	}
	if hlen > 20 {
		dissectIPOptions(it, tvb, 20, hlen)
	}
	it.SetText("Internet Protocol Version 4, Src: %s, Dst: %s", srcA, dstA)
	if ttl == 0 && !pi.InErrorPkt {
		it.AddExpert(eiIPTTLZero, "")
	}
	if !pi.InErrorPkt {
		pi.SetNetAddrs(srcA, dstA)
	}

	payloadLen := totalLen - hlen
	if payloadLen < 0 || hlen > tvb.Reported() {
		return tvb.Len()
	}
	reported := min(payloadLen, tvb.Reported()-hlen)
	payload := tvb.Sub(hlen, reported)
	// The bytes after totalLen are link-layer padding, not ours.
	consumed := hlen + reported

	more := flags&1 != 0
	if fragOff > 0 || more {
		if IPDefragment && !pi.InErrorPkt {
			key := ipFragKey{id: uint32(id), proto: uint8(proto)}
			copy(key.src[:], srcA.Bytes())
			copy(key.dst[:], dstA.Bytes())
			r, in := defragment(pi, protoIP, &ipFragFields, key, payload, fragOff, more, tree)
			if r == nil {
				pi.SetProtocol("IPv4")
				pi.SetInfof("Fragmented IP protocol (proto=%s %d, off=%d, ID=%04x)", ipProtoName(proto), proto, fragOff, id)
				if in != 0 {
					pi.AppendInfo(" [Reassembled in #%d]", in)
				}
				pi.Call(DataHandle, payload, tree)
				return consumed
			}
			payload = r
		} else if fragOff > 0 {
			pi.SetProtocol("IPv4")
			pi.SetInfof("Fragmented IP protocol (proto=%s %d, off=%d, ID=%04x)", ipProtoName(proto), proto, fragOff, id)
			pi.Call(DataHandle, payload, tree)
			return consumed
		}
	}
	if pi.InErrorPkt && payload.Len() == 0 {
		return consumed
	}
	if _, ok := IPProtoTable.Try(proto, payload, pi, tree); !ok {
		if !pi.InErrorPkt {
			pi.SetInfof("%s (%d)", ipProtoName(proto), proto)
		}
		pi.Call(DataHandle, payload, tree)
	}
	return consumed
}

func ipProtoName(p uint64) string {
	if s, ok := IPProtos[p]; ok {
		return s
	}
	return "Unknown"
}

func dscpShortName(v uint64) string {
	if s, ok := dscpShort[v]; ok {
		return s
	}
	return "Unknown"
}

// bitsPrefix renders the bit pattern of mask within a width-bit value.
func bitsPrefix(raw, mask uint64, width int) string {
	f := &d.FieldDef{Bitmask: mask, ParentBits: width}
	return f.BitPattern(raw)
}

var ipOptNames = map[uint64]string{0: "End of Options List (EOL)", 1: "No Operation (NOP)", 7: "Record Route",
	68: "Time Stamp", 130: "Security", 131: "Loose Source Route", 137: "Strict Source Route",
	136: "Stream ID", 148: "Router Alert", 25: "Quick-Start", 133: "Commercial Security"}

func dissectIPOptions(it *d.Node, tvb *d.Tvb, off, end int) {
	ot, _ := it.AddBytes(hfIPOpts, tvb, off, end-off)
	ot.SetText("Options: (%d bytes)", end-off)
	for off < end {
		typ := tvb.U8(off)
		name := ipOptNames[uint64(typ)]
		if name == "" {
			name = "Unknown"
		}
		if typ == 0 || typ == 1 {
			n := ot.AddText(tvb, off, 1, "IP Option - %s", name)
			n.AddUint(hfIPOptType, tvb, off, 1)
			off++
			if typ == 0 {
				break
			}
			continue
		}
		l := int(tvb.U8(off + 1))
		if l < 2 || off+l > end {
			ot.AddText(tvb, off, end-off, "IP Option - %s (bad length %d)", name, l)
			return
		}
		n := ot.AddText(tvb, off, l, "IP Option - %s (%d bytes)", name, l)
		n.AddUint(hfIPOptType, tvb, off, 1)
		n.AddUint(hfIPOptLen, tvb, off+1, 1)
		if typ == 148 && l == 4 {
			n.AddUint(hfIPOptRA, tvb, off+2, 2)
		}
		off += l
	}
}
