package proto

import (
	"encoding/binary"
	"fmt"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	dnsTypes = map[uint64]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT",
		17: "RP", 18: "AFSDB", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC", 33: "SRV", 35: "NAPTR", 36: "KX",
		37: "CERT", 39: "DNAME", 41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG",
		47: "NSEC", 48: "DNSKEY", 49: "DHCID", 50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 55: "HIP",
		59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 65: "HTTPS", 99: "SPF",
		249: "TKEY", 250: "TSIG", 251: "IXFR", 252: "AXFR", 255: "ANY", 256: "URI", 257: "CAA", 32768: "TA", 32769: "DLV"}
	dnsClasses = map[uint64]string{1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}
	dnsOpcodes = map[uint64]string{0: "Standard query", 1: "Inverse query", 2: "Server status request", 4: "Zone change notification", 5: "Dynamic update", 6: "DNS Stateful operations (DSO)"}
	dnsRcodes  = map[uint64]string{0: "No error", 1: "Format error", 2: "Server failure", 3: "No such name", 4: "Not implemented",
		5: "Refused", 6: "Name exists", 7: "RRset exists", 8: "RRset does not exist", 9: "Not authoritative", 10: "Name out of zone",
		16: "Bad OPT version or TSIG signature failure", 17: "Key not recognized", 18: "Signature out of time window", 23: "Bad server cookie"}
	dnsOptCodes = map[uint64]string{3: "NSID", 8: "CSUBNET - Client subnet", 9: "EXPIRE", 10: "COOKIE", 11: "EDNS TCP keepalive",
		12: "PADDING", 13: "CHAIN", 14: "EDNS KEY TAG", 15: "Extended DNS Error", 18: "REPORT-CHANNEL"}
	svcbKeys = map[uint64]string{0: "mandatory", 1: "alpn", 2: "no-default-alpn", 3: "port", 4: "ipv4hint", 5: "ech", 6: "ipv6hint", 7: "dohpath", 8: "ohttp"}

	protoDNS   = d.RegisterProto("Domain Name System", "DNS", "dns")
	protoMDNS  = d.RegisterProto("Multicast Domain Name System", "mDNS", "mdns")
	protoLLMNR = d.RegisterProto("Link-local Multicast Name Resolution", "LLMNR", "llmnr")

	hfDNSLength    = protoDNS.Field("dns.length", "Length", d.FtUint16)
	hfDNSID        = protoDNS.Field("dns.id", "Transaction ID", d.FtUint16, d.WithBase(d.BaseHex))
	hfDNSFlags     = protoDNS.Field("dns.flags", "Flags", d.FtUint16, d.WithBase(d.BaseHex))
	hfDNSFResponse = protoDNS.Field("dns.flags.response", "Response", d.FtBool, d.WithMask(0x8000), d.WithParentBits(16), d.WithTFS(&d.TrueFalse{True: "Message is a response", False: "Message is a query"}))
	hfDNSFOpcode   = protoDNS.Field("dns.flags.opcode", "Opcode", d.FtUint16, d.WithMask(0x7800), d.WithVS(dnsOpcodes))
	hfDNSFAuth     = protoDNS.Field("dns.flags.authoritative", "Authoritative", d.FtBool, d.WithMask(0x0400), d.WithParentBits(16), d.WithTFS(&d.TrueFalse{True: "Server is an authority for domain", False: "Server is not an authority for domain"}))
	hfDNSFTrunc    = protoDNS.Field("dns.flags.truncated", "Truncated", d.FtBool, d.WithMask(0x0200), d.WithParentBits(16), d.WithTFS(&d.TrueFalse{True: "Message is truncated", False: "Message is not truncated"}))
	hfDNSFRD       = protoDNS.Field("dns.flags.recdesired", "Recursion desired", d.FtBool, d.WithMask(0x0100), d.WithParentBits(16), d.WithTFS(&d.TrueFalse{True: "Do query recursively", False: "Don't do query recursively"}))
	hfDNSFRA       = protoDNS.Field("dns.flags.recavail", "Recursion available", d.FtBool, d.WithMask(0x0080), d.WithParentBits(16), d.WithTFS(&d.TrueFalse{True: "Server can do recursive queries", False: "Server can't do recursive queries"}))
	hfDNSFZ        = protoDNS.Field("dns.flags.z", "Z", d.FtBool, d.WithMask(0x0040), d.WithParentBits(16), d.WithTFS(&d.TrueFalse{True: "reserved (1)", False: "reserved (0)"}))
	hfDNSFAD       = protoDNS.Field("dns.flags.authenticated", "Answer authenticated", d.FtBool, d.WithMask(0x0020), d.WithParentBits(16), d.WithTFS(&d.TrueFalse{True: "Answer/authority portion was authenticated by the server", False: "Answer/authority portion was not authenticated by the server"}))
	hfDNSFCD       = protoDNS.Field("dns.flags.checkdisable", "Non-authenticated data", d.FtBool, d.WithMask(0x0010), d.WithParentBits(16), d.WithTFS(&d.TrueFalse{True: "Acceptable", False: "Unacceptable"}))
	hfDNSFRcode    = protoDNS.Field("dns.flags.rcode", "Reply code", d.FtUint16, d.WithMask(0x000f), d.WithVS(dnsRcodes))
	hfDNSQueries   = protoDNS.Field("dns.count.queries", "Questions", d.FtUint16)
	hfDNSAnswers   = protoDNS.Field("dns.count.answers", "Answer RRs", d.FtUint16)
	hfDNSAuthRR    = protoDNS.Field("dns.count.auth_rr", "Authority RRs", d.FtUint16)
	hfDNSAddRR     = protoDNS.Field("dns.count.add_rr", "Additional RRs", d.FtUint16)
	hfDNSQryName   = protoDNS.Field("dns.qry.name", "Name", d.FtString)
	hfDNSQryNameLn = protoDNS.Field("dns.qry.name.len", "Name Length", d.FtUint16)
	hfDNSLabels    = protoDNS.Field("dns.count.labels", "Label Count", d.FtUint16)
	hfDNSQryType   = protoDNS.Field("dns.qry.type", "Type", d.FtUint16, d.WithVS(dnsTypes))
	hfDNSQryClass  = protoDNS.Field("dns.qry.class", "Class", d.FtUint16, d.WithMask(0x7fff), d.WithBase(d.BaseHex), d.WithVS(dnsClasses))
	hfDNSQryQU     = protoDNS.Field("dns.qry.qu", "\"QU\" question", d.FtBool, d.WithMask(0x8000), d.WithParentBits(16), d.WithTFS(TFSUnicastMulticast))
	hfDNSRespName  = protoDNS.Field("dns.resp.name", "Name", d.FtString)
	hfDNSRespType  = protoDNS.Field("dns.resp.type", "Type", d.FtUint16, d.WithVS(dnsTypes))
	hfDNSRespClass = protoDNS.Field("dns.resp.class", "Class", d.FtUint16, d.WithMask(0x7fff), d.WithBase(d.BaseHex), d.WithVS(dnsClasses))
	hfDNSCacheFl   = protoDNS.Field("dns.resp.cache_flush", "Cache flush", d.FtBool, d.WithMask(0x8000), d.WithParentBits(16), d.WithTFS(d.TFSTrue))
	hfDNSTTL       = protoDNS.Field("dns.resp.ttl", "Time to live", d.FtInt32, d.WithUnit("seconds"))
	hfDNSRespLen   = protoDNS.Field("dns.resp.len", "Data length", d.FtUint16)
	hfDNSA         = protoDNS.Field("dns.a", "Address", d.FtIPv4)
	hfDNSAAAA      = protoDNS.Field("dns.aaaa", "AAAA Address", d.FtIPv6)
	hfDNSCNAME     = protoDNS.Field("dns.cname", "CNAME", d.FtString)
	hfDNSNS        = protoDNS.Field("dns.ns", "Name Server", d.FtString)
	hfDNSPTR       = protoDNS.Field("dns.ptr.domain_name", "Domain Name", d.FtString)
	hfDNSMXPref    = protoDNS.Field("dns.mx.preference", "Preference", d.FtUint16)
	hfDNSMX        = protoDNS.Field("dns.mx.mail_exchange", "Mail Exchange", d.FtString)
	hfDNSTXT       = protoDNS.Field("dns.txt", "TXT", d.FtString)
	hfDNSTXTLen    = protoDNS.Field("dns.txt.length", "TXT Length", d.FtUint8)
	hfDNSSOAM      = protoDNS.Field("dns.soa.mname", "Primary name server", d.FtString)
	hfDNSSOAR      = protoDNS.Field("dns.soa.rname", "Responsible authority's mailbox", d.FtString)
	hfDNSSOASerial = protoDNS.Field("dns.soa.serial_number", "Serial Number", d.FtUint32)
	hfDNSSOARefr   = protoDNS.Field("dns.soa.refresh_interval", "Refresh Interval", d.FtUint32)
	hfDNSSOARetry  = protoDNS.Field("dns.soa.retry_interval", "Retry Interval", d.FtUint32)
	hfDNSSOAExp    = protoDNS.Field("dns.soa.expire_limit", "Expire limit", d.FtUint32)
	hfDNSSOAMin    = protoDNS.Field("dns.soa.minimum_ttl", "Minimum TTL", d.FtUint32)
	hfDNSSRVPrio   = protoDNS.Field("dns.srv.priority", "Priority", d.FtUint16)
	hfDNSSRVWeight = protoDNS.Field("dns.srv.weight", "Weight", d.FtUint16)
	hfDNSSRVPort   = protoDNS.Field("dns.srv.port", "Port", d.FtUint16)
	hfDNSSRVTarget = protoDNS.Field("dns.srv.target", "Target", d.FtString)
	hfDNSCAAFlags  = protoDNS.Field("dns.caa.flags", "CAA Flags", d.FtUint8, d.WithBase(d.BaseHex))
	hfDNSCAATag    = protoDNS.Field("dns.caa.tag", "Tag", d.FtString)
	hfDNSCAAValue  = protoDNS.Field("dns.caa.value", "Value", d.FtString)
	hfDNSRData     = protoDNS.Field("dns.data", "Data", d.FtBytes)
	hfDNSUDPSize   = protoDNS.Field("dns.rr.udp_payload_size", "UDP payload size", d.FtUint16)
	hfDNSExtRcode  = protoDNS.Field("dns.resp.ext_rcode", "Higher bits in extended RCODE", d.FtUint8, d.WithBase(d.BaseHex))
	hfDNSEDNSVer   = protoDNS.Field("dns.resp.edns0_version", "EDNS0 version", d.FtUint8)
	hfDNSDO        = protoDNS.Field("dns.resp.z.do", "DO bit", d.FtBool, d.WithMask(0x8000), d.WithParentBits(16), d.WithTFS(&d.TrueFalse{True: "Accepts DNSSEC security RRs", False: "Cannot handle DNSSEC security RRs"}))
	hfDNSOptCode   = protoDNS.Field("dns.opt.code", "Option: Code", d.FtUint16, d.WithVS(dnsOptCodes))
	hfDNSOptLen    = protoDNS.Field("dns.opt.len", "Option: Length", d.FtUint16)
	hfDNSOptData   = protoDNS.Field("dns.opt.data", "Option: Data", d.FtBytes)
	hfDNSOptECSFam = protoDNS.Field("dns.opt.client.family", "Family", d.FtUint16, d.WithVS(map[uint64]string{1: "IPv4", 2: "IPv6"}))
	hfDNSOptECSNet = protoDNS.Field("dns.opt.client.netmask", "Source Netmask", d.FtUint8)
	hfDNSOptECSSco = protoDNS.Field("dns.opt.client.scope", "Scope Netmask", d.FtUint8)
	hfDNSOptECSA4  = protoDNS.Field("dns.opt.client.addr4", "Client Subnet", d.FtIPv4)
	hfDNSOptECSA6  = protoDNS.Field("dns.opt.client.addr6", "Client Subnet", d.FtIPv6)
	hfDNSOptCookie = protoDNS.Field("dns.opt.cookie.client", "Client Cookie", d.FtBytes)
	hfDNSOptEDE    = protoDNS.Field("dns.opt.ede.info_code", "Info Code", d.FtUint16)
	hfDNSOptEDEtxt = protoDNS.Field("dns.opt.ede.extra_text", "Extra Text", d.FtString)
	hfSVCBPrio     = protoDNS.Field("dns.svcb.svcpriority", "SvcPriority", d.FtUint16)
	hfSVCBTarget   = protoDNS.Field("dns.svcb.targetname", "TargetName", d.FtString)
	hfSVCBKey      = protoDNS.Field("dns.svcb.svcparam.key", "SvcParamKey", d.FtUint16, d.WithVS(svcbKeys))
	hfSVCBLen      = protoDNS.Field("dns.svcb.svcparam.value.length", "SvcParamValue length", d.FtUint16)
	hfSVCBALPN     = protoDNS.Field("dns.svcb.svcparam.alpn.identifier", "ALPN", d.FtString)
	hfSVCBPort     = protoDNS.Field("dns.svcb.svcparam.port", "Port", d.FtUint16)
	hfSVCBIPv4     = protoDNS.Field("dns.svcb.svcparam.ipv4hint.ip", "IP", d.FtIPv4)
	hfSVCBIPv6     = protoDNS.Field("dns.svcb.svcparam.ipv6hint.ip", "IP", d.FtIPv6)
	hfSVCBECH      = protoDNS.Field("dns.svcb.svcparam.ech", "ECHConfigList", d.FtBytes)
	hfSVCBDoHPath  = protoDNS.Field("dns.svcb.svcparam.dohpath", "DoH path", d.FtString)
	hfDNSKeyFlags  = protoDNS.Field("dns.dnskey.flags", "Flags", d.FtUint16, d.WithBase(d.BaseHex))
	hfDNSKeyAlg    = protoDNS.Field("dns.dnskey.algorithm", "Algorithm", d.FtUint8)
	hfDNSKeyTag    = protoDNS.Field("dns.dnskey.key_id", "Key id", d.FtUint16)
	hfDNSRRSIGType = protoDNS.Field("dns.rrsig.type_covered", "Type Covered", d.FtUint16, d.WithVS(dnsTypes))
	hfDNSRRSIGAlg  = protoDNS.Field("dns.rrsig.algorithm", "Algorithm", d.FtUint8)
	hfDNSRRSIGName = protoDNS.Field("dns.rrsig.signers_name", "Signer's name", d.FtString)
	hfDNSDSTag     = protoDNS.Field("dns.ds.key_id", "Key id", d.FtUint16)
	hfDNSDSDigType = protoDNS.Field("dns.ds.digest_type", "Digest Type", d.FtUint8)
	hfDNSRespIn    = protoDNS.Field("dns.response_in", "Response In", d.FtFrameNum)
	hfDNSRespTo    = protoDNS.Field("dns.response_to", "Request In", d.FtFrameNum)
	hfDNSTime      = protoDNS.Field("dns.time", "Time", d.FtRelTime)
	hfDNSUnsolic   = protoDNS.Field("dns.unsolicited", "Unsolicited", d.FtNone)
	hfDNSRetrans   = protoDNS.Field("dns.retransmission", "Retransmission", d.FtBool)
	hfDNSRetransIn = protoDNS.Field("dns.retransmit_request_in", "Retransmitted request. Original request in", d.FtFrameNum)
	eiDNSNoResp    = protoDNS.Expert("dns.response.no_response", d.GroupSequence, d.SevNote, "No response seen to DNS query")
	eiDNSRetrans   = protoDNS.Expert("dns.retransmission.expert", d.GroupSequence, d.SevNote, "Retransmitted DNS query")
	eiDNSLoop      = protoDNS.Expert("dns.name.compression_loop", d.GroupMalformed, d.SevError, "Name compression loop")

	// TFSUnicastMulticast describes the mDNS QU bit.
	TFSUnicastMulticast = &d.TrueFalse{True: "Unicast responses requested", False: "Multicast responses requested"}

	dnsUDPHandle = d.RegisterHandle("dns", d.NewHandle(protoDNS, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		return dissectDNSMessage(tvb, pi, tree, protoDNS, false)
	}))
)

func init() {
	UDPPortTable.Add(53, dnsUDPHandle)
	UDPPortTable.Add(5353, d.NewHandle(protoMDNS, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		return dissectDNSMessage(tvb, pi, tree, protoMDNS, false)
	}))
	UDPPortTable.Add(5355, d.NewHandle(protoLLMNR, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		return dissectDNSMessage(tvb, pi, tree, protoLLMNR, false)
	}))
	TCPPortTable.Add(53, d.RegisterHandle("dns-tcp", d.NewHandle(protoDNS, dissectDNSTCP)))
	TCPPortTable.Add(5355, d.NewHandle(protoLLMNR, dissectDNSTCP))
}

// dissectDNSTCP handles DNS over TCP (and DoT once decrypted): each message
// carries a 2-byte length.
func dissectDNSTCP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	return TCPDissectPDUs(tvb, pi, tree, 2, func(tvb *d.Tvb, off int) int {
		return 2 + int(tvb.U16(off))
	}, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		return dissectDNSMessage(tvb.Sub(2, -1), pi, tree, protoDNS, true)
	})
}

// DissectDNSMessage dissects a DNS message (used by DoH too).
func DissectDNSMessage(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	return dissectDNSMessage(tvb, pi, tree, protoDNS, false)
}

// dnsName reads a possibly compressed name at off. It returns the name, the
// number of bytes used at off and the label count.
func dnsName(tvb *d.Tvb, off int) (name string, used int, labels int, loop bool) {
	var parts []string
	pos := off
	jumped := false
	hops := 0
	for {
		l := int(tvb.U8(pos))
		switch {
		case l == 0:
			if !jumped {
				used = pos + 1 - off
			}
			if len(parts) == 0 {
				return "<Root>", used, 0, false
			}
			return strings.Join(parts, "."), used, len(parts), false
		case l&0xc0 == 0xc0:
			ptr := int(tvb.U16(pos) & 0x3fff)
			if !jumped {
				used = pos + 2 - off
			}
			jumped = true
			hops++
			if hops > 64 || ptr >= tvb.Len() {
				return strings.Join(parts, ".") + "<loop>", used, len(parts), true
			}
			pos = ptr
		case l&0xc0 != 0:
			// Extended label types are not supported.
			if !jumped {
				used = pos + 1 - off
			}
			return strings.Join(parts, ".") + "<unknown extended label>", used, len(parts), false
		default:
			parts = append(parts, labelString(tvb.Bytes(pos+1, l)))
			pos += 1 + l
			if len(parts) > 128 {
				return strings.Join(parts, "."), used, len(parts), true
			}
		}
	}
}

func labelString(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '.':
			sb.WriteString("\\.")
		case c < 0x21 || c > 0x7e:
			fmt.Fprintf(&sb, "\\%03d", c)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

type dnsKey struct {
	a, b   d.Address
	pa, pb uint32
	id     uint16
}

type dnsMatch struct {
	reqFrame  uint32
	reqTS     int64
	respFrame uint32
	retransOf uint32
}

func dnsTransKey(pi *d.PacketInfo, id uint16, response bool) dnsKey {
	if response {
		return dnsKey{pi.Dst, pi.Src, pi.DstPort, pi.SrcPort, id}
	}
	return dnsKey{pi.Src, pi.Dst, pi.SrcPort, pi.DstPort, id}
}

func dissectDNSMessage(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node, p *d.Proto, overTCP bool) int {
	if tvb.Len() < 12 {
		return 0
	}
	id := tvb.U16(0)
	flags := tvb.U16(2)
	qd, an, ns, ar := int(tvb.U16(4)), int(tvb.U16(6)), int(tvb.U16(8)), int(tvb.U16(10))
	response := flags&0x8000 != 0
	opcode := uint64(flags>>11) & 0xf
	rcode := uint64(flags & 0xf)
	dt := tree.AddProtocol(p, tvb, 0, -1)
	name := map[*d.Proto]string{protoDNS: "DNS", protoMDNS: "MDNS", protoLLMNR: "LLMNR"}[p]
	pi.SetProtocol(name)
	label := p.Name
	if response {
		label += " (response)"
	} else {
		label += " (query)"
	}
	dt.SetText("%s", label)
	if overTCP {
		dt.AddUintValue(hfDNSLength, nil, 0, 0, uint64(tvb.Len()))
	}
	dt.AddUint(hfDNSID, tvb, 0, 2)
	fn := dt.AddUintValue(hfDNSFlags, tvb, 2, 2, uint64(flags))
	op := dnsOpcodes[opcode]
	if op == "" {
		op = "Unknown operation"
	}
	ftext := op
	if response {
		ftext += " response, " + rcodeName(rcode)
	}
	fn.SetText("Flags: 0x%04x %s", flags, ftext)
	fn.AddBits(hfDNSFResponse, tvb, 2, 2, uint64(flags))
	fn.AddBits(hfDNSFOpcode, tvb, 2, 2, uint64(flags))
	if response {
		fn.AddBits(hfDNSFAuth, tvb, 2, 2, uint64(flags))
	}
	fn.AddBits(hfDNSFTrunc, tvb, 2, 2, uint64(flags))
	fn.AddBits(hfDNSFRD, tvb, 2, 2, uint64(flags))
	if response {
		fn.AddBits(hfDNSFRA, tvb, 2, 2, uint64(flags))
	}
	fn.AddBits(hfDNSFZ, tvb, 2, 2, uint64(flags))
	if response {
		fn.AddBits(hfDNSFAD, tvb, 2, 2, uint64(flags))
	}
	fn.AddBits(hfDNSFCD, tvb, 2, 2, uint64(flags))
	if response {
		fn.AddBits(hfDNSFRcode, tvb, 2, 2, uint64(flags))
	}
	dt.AddUint(hfDNSQueries, tvb, 4, 2)
	dt.AddUint(hfDNSAnswers, tvb, 6, 2)
	dt.AddUint(hfDNSAuthRR, tvb, 8, 2)
	dt.AddUint(hfDNSAddRR, tvb, 10, 2)

	var info strings.Builder
	info.WriteString(op)
	if response {
		info.WriteString(" response")
	}
	fmt.Fprintf(&info, " 0x%04x", id)
	if response && rcode != 0 {
		info.WriteString(" " + rcodeName(rcode))
	}
	off := 12
	mdns := p == protoMDNS
	if qd > 0 {
		qt := dt.AddText(tvb, off, 0, "Queries")
		start := off
		for i := 0; i < qd && tvb.Remaining(off) > 0; i++ {
			n, err := dnsQuestion(tvb, off, qt, mdns, &info)
			if err {
				break
			}
			off += n
		}
		qt.SetLen(off - start)
	}
	sections := []struct {
		title string
		count int
	}{{"Answers", an}, {"Authoritative nameservers", ns}, {"Additional records", ar}}
	for si, sec := range sections {
		if sec.count == 0 {
			continue
		}
		st := dt.AddText(tvb, off, 0, "%s", sec.title)
		start := off
		for i := 0; i < sec.count && tvb.Remaining(off) > 0; i++ {
			n, ok := dnsRR(tvb, off, st, mdns, si, &info, pi)
			if !ok {
				break
			}
			off += n
		}
		st.SetLen(off - start)
	}
	dnsMatchTransaction(pi, dt, id, response, opcode)
	if !mdns || pi.WantColumns() {
		pi.SetInfo(info.String())
	}
	return tvb.Len()
}

func rcodeName(r uint64) string {
	if s, ok := dnsRcodes[r]; ok {
		return s
	}
	return fmt.Sprintf("Unknown (%d)", r)
}

func typeName(t uint64) string {
	if s, ok := dnsTypes[t]; ok {
		return s
	}
	return fmt.Sprintf("Unknown (%d)", t)
}

func classLabel(c uint64) string {
	if s, ok := dnsClasses[c]; ok {
		return s
	}
	return fmt.Sprintf("0x%04x", c)
}

func dnsQuestion(tvb *d.Tvb, off int, qt *d.Node, mdns bool, info *strings.Builder) (int, bool) {
	name, used, labels, loop := dnsName(tvb, off)
	typ := uint64(tvb.U16(off + used))
	class := tvb.U16(off + used + 2)
	total := used + 4
	n := qt.AddText(tvb, off, total, "%s: type %s, class %s", name, typeName(typ), classLabel(uint64(class&0x7fff)))
	n.AddValue(hfDNSQryName, tvb, off, used, d.StringValue(name))
	if loop {
		n.AddExpert(eiDNSLoop, "")
	}
	n.AddGenerated(hfDNSQryNameLn, d.Value{U: uint64(len(name))})
	n.AddGenerated(hfDNSLabels, d.Value{U: uint64(labels)})
	n.AddUint(hfDNSQryType, tvb, off+used, 2)
	cn := n.AddBits(hfDNSQryClass, tvb, off+used+2, 2, uint64(class))
	if !mdns {
		cn.SetText("Class: %s (0x%04x)", classLabel(uint64(class)), class)
	}
	if mdns {
		n.AddBits(hfDNSQryQU, tvb, off+used+2, 2, uint64(class))
	}
	info.WriteString(" " + typeName(typ) + " " + name)
	return total, loop
}

func dnsRR(tvb *d.Tvb, off int, st *d.Node, mdns bool, section int, info *strings.Builder, pi *d.PacketInfo) (int, bool) {
	name, used, _, loop := dnsName(tvb, off)
	typ := uint64(tvb.U16(off + used))
	class := tvb.U16(off + used + 2)
	ttlRaw := tvb.U32(off + used + 4)
	rdlen := int(tvb.U16(off + used + 8))
	rd := off + used + 10
	total := used + 10 + rdlen
	if typ == 41 {
		return dnsOPT(tvb, off, used, st, rd, rdlen, class, ttlRaw, info), true
	}
	rr := st.AddText(tvb, off, total, "%s: type %s, class %s", name, typeName(typ), classLabel(uint64(class&0x7fff)))
	rr.AddValue(hfDNSRespName, tvb, off, used, d.StringValue(name))
	if loop {
		rr.AddExpert(eiDNSLoop, "")
	}
	rr.AddUint(hfDNSRespType, tvb, off+used, 2)
	cn := rr.AddBits(hfDNSRespClass, tvb, off+used+2, 2, uint64(class))
	if !mdns {
		cn.SetText("Class: %s (0x%04x)", classLabel(uint64(class)), class)
	}
	if mdns {
		rr.AddBits(hfDNSCacheFl, tvb, off+used+2, 2, uint64(class))
	}
	tn := rr.AddUintValue(hfDNSTTL, tvb, off+used+4, 4, uint64(ttlRaw))
	tn.SetText("Time to live: %d (%s)", int32(ttlRaw), ttlHuman(int64(int32(ttlRaw))))
	rr.AddUint(hfDNSRespLen, tvb, off+used+8, 2)
	if !tvb.Has(rd, rdlen) {
		return total, false
	}
	summary := dnsRData(tvb, rd, rdlen, typ, rr)
	if summary != "" {
		rr.AppendText(", %s", summary)
	}
	if section == 0 || (section == 1 && typ == 6) {
		info.WriteString(" " + typeName(typ))
		if s := shortRData(summary); s != "" {
			info.WriteString(" " + s)
		}
	}
	return total, true
}

func ttlHuman(s int64) string {
	if s < 0 {
		return fmt.Sprintf("%d seconds", s)
	}
	parts := []string{}
	for _, u := range []struct {
		n    int64
		name string
	}{{86400, "day"}, {3600, "hour"}, {60, "minute"}, {1, "second"}} {
		if v := s / u.n; v > 0 {
			p := fmt.Sprintf("%d %s", v, u.name)
			if v != 1 {
				p += "s"
			}
			parts = append(parts, p)
			s %= u.n
		}
	}
	if len(parts) == 0 {
		return "0 seconds"
	}
	return strings.Join(parts, ", ")
}

// shortRData converts "addr 1.2.3.4" to "1.2.3.4" for the Info column.
func shortRData(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[i+1:]
	}
	return s
}

func dnsRData(tvb *d.Tvb, rd, l int, typ uint64, rr *d.Node) string {
	rdt := tvb.Sub(0, rd+l) // names may point anywhere earlier in the message
	switch typ {
	case 1:
		if l == 4 {
			_, a := rr.AddIPv4(hfDNSA, tvb, rd)
			return "addr " + d.FormatIPv4(a)
		}
	case 28:
		if l == 16 {
			_, a := rr.AddBytes(hfDNSAAAA, tvb, rd, 16)
			return "addr " + d.FormatIPv6(a)
		}
	case 2, 5, 12, 39:
		n, used, _, _ := dnsName(rdt, rd)
		hf := map[uint64]*d.FieldDef{2: hfDNSNS, 5: hfDNSCNAME, 12: hfDNSPTR, 39: hfDNSCNAME}[typ]
		rr.AddValue(hf, tvb, rd, used, d.StringValue(n))
		return map[uint64]string{2: "ns", 5: "cname", 12: "ptr", 39: "dname"}[typ] + " " + n
	case 15:
		_, pref := rr.AddUint(hfDNSMXPref, tvb, rd, 2)
		n, used, _, _ := dnsName(rdt, rd+2)
		rr.AddValue(hfDNSMX, tvb, rd+2, used, d.StringValue(n))
		return fmt.Sprintf("preference %d, mx %s", pref, n)
	case 16, 99:
		var texts []string
		for p := rd; p < rd+l; {
			tl := int(tvb.U8(p))
			rr.AddUint(hfDNSTXTLen, tvb, p, 1)
			_, s := rr.AddString(hfDNSTXT, tvb, p+1, min(tl, rd+l-p-1))
			texts = append(texts, s)
			p += 1 + tl
		}
		return "txt " + strings.Join(texts, "")
	case 6:
		mn, u1, _, _ := dnsName(rdt, rd)
		rr.AddValue(hfDNSSOAM, tvb, rd, u1, d.StringValue(mn))
		rn, u2, _, _ := dnsName(rdt, rd+u1)
		rr.AddValue(hfDNSSOAR, tvb, rd+u1, u2, d.StringValue(rn))
		p := rd + u1 + u2
		rr.AddUint(hfDNSSOASerial, tvb, p, 4)
		rr.AddUint(hfDNSSOARefr, tvb, p+4, 4)
		rr.AddUint(hfDNSSOARetry, tvb, p+8, 4)
		rr.AddUint(hfDNSSOAExp, tvb, p+12, 4)
		rr.AddUint(hfDNSSOAMin, tvb, p+16, 4)
		return "mname " + mn
	case 33:
		_, prio := rr.AddUint(hfDNSSRVPrio, tvb, rd, 2)
		_, w := rr.AddUint(hfDNSSRVWeight, tvb, rd+2, 2)
		_, port := rr.AddUint(hfDNSSRVPort, tvb, rd+4, 2)
		n, used, _, _ := dnsName(rdt, rd+6)
		rr.AddValue(hfDNSSRVTarget, tvb, rd+6, used, d.StringValue(n))
		return fmt.Sprintf("priority %d, weight %d, port %d, target %s", prio, w, port, n)
	case 257:
		rr.AddUint(hfDNSCAAFlags, tvb, rd, 1)
		tl := int(tvb.U8(rd + 1))
		_, tag := rr.AddString(hfDNSCAATag, tvb, rd+2, tl)
		_, v := rr.AddString(hfDNSCAAValue, tvb, rd+2+tl, l-2-tl)
		return fmt.Sprintf("caa %s %q", tag, v)
	case 64, 65:
		return dnsSVCB(tvb, rdt, rd, l, rr)
	case 48, 257 + 1000:
		rr.AddUint(hfDNSKeyFlags, tvb, rd, 2)
		rr.AddUint(hfDNSKeyAlg, tvb, rd+3, 1)
		rr.AddGenerated(hfDNSKeyTag, d.Value{U: uint64(keyTag(tvb.Bytes(rd, l)))})
		return ""
	case 46:
		rr.AddUint(hfDNSRRSIGType, tvb, rd, 2)
		rr.AddUint(hfDNSRRSIGAlg, tvb, rd+2, 1)
		n, used, _, _ := dnsName(rdt, rd+18)
		rr.AddValue(hfDNSRRSIGName, tvb, rd+18, used, d.StringValue(n))
		return ""
	case 43:
		rr.AddUint(hfDNSDSTag, tvb, rd, 2)
		rr.AddUint(hfDNSDSDigType, tvb, rd+3, 1)
		return ""
	}
	if l > 0 {
		rr.AddBytes(hfDNSRData, tvb, rd, l)
	}
	return ""
}

// keyTag computes the DNSKEY key tag (RFC 4034 appendix B).
func keyTag(b []byte) uint16 {
	var ac uint32
	for i, c := range b {
		if i&1 == 1 {
			ac += uint32(c)
		} else {
			ac += uint32(c) << 8
		}
	}
	ac += ac >> 16 & 0xffff
	return uint16(ac & 0xffff)
}

func dnsSVCB(tvb, rdt *d.Tvb, rd, l int, rr *d.Node) string {
	_, prio := rr.AddUint(hfSVCBPrio, tvb, rd, 2)
	n, used, _, _ := dnsName(rdt, rd+2)
	rr.AddValue(hfSVCBTarget, tvb, rd+2, used, d.StringValue(n))
	var params []string
	for p := rd + 2 + used; p+4 <= rd+l; {
		key := uint64(tvb.U16(p))
		vl := int(tvb.U16(p + 2))
		kn := svcbKeys[key]
		if kn == "" {
			kn = fmt.Sprintf("key%d", key)
		}
		pn := rr.AddText(tvb, p, 4+vl, "SvcParam: %s", kn)
		pn.AddUint(hfSVCBKey, tvb, p, 2)
		pn.AddUint(hfSVCBLen, tvb, p+2, 2)
		v := p + 4
		switch key {
		case 1:
			var ids []string
			for q := v; q < v+vl; {
				il := int(tvb.U8(q))
				_, s := pn.AddString(hfSVCBALPN, tvb, q+1, il)
				ids = append(ids, s)
				q += 1 + il
			}
			params = append(params, "alpn="+strings.Join(ids, ","))
		case 3:
			_, port := pn.AddUint(hfSVCBPort, tvb, v, 2)
			params = append(params, fmt.Sprintf("port=%d", port))
		case 4:
			for q := v; q+4 <= v+vl; q += 4 {
				pn.AddIPv4(hfSVCBIPv4, tvb, q)
			}
			params = append(params, "ipv4hint")
		case 5:
			pn.AddBytes(hfSVCBECH, tvb, v, vl)
			params = append(params, "ech")
		case 6:
			for q := v; q+16 <= v+vl; q += 16 {
				pn.AddBytes(hfSVCBIPv6, tvb, q, 16)
			}
			params = append(params, "ipv6hint")
		case 7:
			_, s := pn.AddString(hfSVCBDoHPath, tvb, v, vl)
			params = append(params, "dohpath="+s)
		default:
			params = append(params, kn)
		}
		p += 4 + vl
	}
	s := fmt.Sprintf("priority %d, target %s", prio, n)
	if len(params) > 0 {
		s += ", " + strings.Join(params, " ")
	}
	return s
}

func dnsOPT(tvb *d.Tvb, off, used int, st *d.Node, rd, rdlen int, class uint16, ttl uint32, info *strings.Builder) int {
	total := used + 10 + rdlen
	rr := st.AddText(tvb, off, total, "<Root>: type OPT")
	rr.AddValue(hfDNSRespName, tvb, off, used, d.StringValue("<Root>"))
	rr.AddUint(hfDNSRespType, tvb, off+used, 2)
	rr.AddUint(hfDNSUDPSize, tvb, off+used+2, 2)
	rr.AddUintValue(hfDNSExtRcode, tvb, off+used+4, 1, uint64(ttl>>24))
	rr.AddUintValue(hfDNSEDNSVer, tvb, off+used+5, 1, uint64(ttl>>16&0xff))
	rr.AddBits(hfDNSDO, tvb, off+used+6, 2, uint64(ttl&0xffff))
	rr.AddUint(hfDNSRespLen, tvb, off+used+8, 2)
	info.WriteString(" OPT")
	_ = class
	for p := rd; p+4 <= rd+rdlen && tvb.Has(p, 4); {
		code := uint64(tvb.U16(p))
		ol := int(tvb.U16(p + 2))
		name := dnsOptCodes[code]
		if name == "" {
			name = fmt.Sprintf("Unknown (%d)", code)
		}
		on := rr.AddText(tvb, p, 4+ol, "Option: %s", name)
		on.AddUint(hfDNSOptCode, tvb, p, 2)
		on.AddUint(hfDNSOptLen, tvb, p+2, 2)
		v := p + 4
		if !tvb.Has(v, ol) {
			break
		}
		switch code {
		case 8:
			if ol >= 4 {
				_, fam := on.AddUint(hfDNSOptECSFam, tvb, v, 2)
				on.AddUint(hfDNSOptECSNet, tvb, v+2, 1)
				on.AddUint(hfDNSOptECSSco, tvb, v+3, 1)
				addr := tvb.Bytes(v+4, ol-4)
				switch fam {
				case 1:
					var a [4]byte
					copy(a[:], addr)
					on.AddValue(hfDNSOptECSA4, tvb, v+4, ol-4, d.Value{U: uint64(binary.BigEndian.Uint32(a[:]))})
				case 2:
					var a [16]byte
					copy(a[:], addr)
					on.AddValue(hfDNSOptECSA6, tvb, v+4, ol-4, d.Value{B: a[:]})
				}
			}
		case 10:
			on.AddBytes(hfDNSOptCookie, tvb, v, min(ol, 8))
		case 15:
			if ol >= 2 {
				on.AddUint(hfDNSOptEDE, tvb, v, 2)
				if ol > 2 {
					on.AddString(hfDNSOptEDEtxt, tvb, v+2, ol-2)
				}
			}
		default:
			if ol > 0 {
				on.AddBytes(hfDNSOptData, tvb, v, ol)
			}
		}
		p += 4 + ol
	}
	return total
}

type dnsState struct {
	open map[dnsKey]*dnsMatch
}

func dnsMatchTransaction(pi *d.PacketInfo, dt *d.Node, id uint16, response bool, opcode uint64) {
	if pi.PortType == d.PortNone || pi.InErrorPkt {
		return
	}
	sess := pi.Sess
	if !pi.Visited {
		st, _ := sess.ProtoState(protoDNS).(*dnsState)
		if st == nil {
			st = &dnsState{open: map[dnsKey]*dnsMatch{}}
			sess.SetProtoState(protoDNS, st)
		}
		k := dnsTransKey(pi, id, response)
		if !response {
			if prev, ok := st.open[k]; ok && prev.respFrame == 0 {
				// Same ID again before an answer: a retransmission.
				sess.SetFrameData(protoDNS, pi.Num, 0, &dnsMatch{retransOf: prev.reqFrame})
			} else {
				m := &dnsMatch{reqFrame: pi.Num, reqTS: pi.TS}
				st.open[k] = m
				sess.SetFrameData(protoDNS, pi.Num, 0, m)
			}
		} else if m, ok := st.open[k]; ok && m.respFrame == 0 {
			m.respFrame = pi.Num
			sess.SetFrameData(protoDNS, pi.Num, 0, &dnsMatch{reqFrame: m.reqFrame, reqTS: m.reqTS, respFrame: pi.Num})
			delete(st.open, k)
		}
	}
	m, _ := sess.FrameData(protoDNS, pi.Num, 0).(*dnsMatch)
	switch {
	case m == nil && response && opcode == 0:
		dt.AddGenerated(hfDNSUnsolic, d.Value{})
	case m == nil:
	case m.retransOf != 0:
		dt.AddGenerated(hfDNSRetrans, d.BoolValue(true)).AddExpert(eiDNSRetrans, "")
		dt.AddGenerated(hfDNSRetransIn, d.Value{U: uint64(m.retransOf)}).SetLink(m.retransOf)
	case !response && m.respFrame != 0:
		dt.AddGenerated(hfDNSRespIn, d.Value{U: uint64(m.respFrame)}).SetLink(m.respFrame)
	case response:
		dt.AddGenerated(hfDNSRespTo, d.Value{U: uint64(m.reqFrame)}).SetLink(m.reqFrame)
		dt.AddGenerated(hfDNSTime, d.RelTimeValue(pi.TS-m.reqTS)).
			SetText("[Time: %s seconds]", d.FormatRelTime(pi.TS-m.reqTS))
	case !response && pi.Visited:
		dt.AddText(nil, 0, 0, "[No response seen]").SetGenerated().AddExpert(eiDNSNoResp, "")
	}
}
