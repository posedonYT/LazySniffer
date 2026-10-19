package proto

import (
	"fmt"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

// ---------------- STP ----------------

var (
	stpTypes     = map[uint64]string{0x00: "Configuration BPDU", 0x80: "Topology Change Notification BPDU", 0x02: "Rapid/Multiple Spanning Tree BPDU"}
	protoSTP     = d.RegisterProto("Spanning Tree Protocol", "STP", "stp")
	hfSTPProto   = protoSTP.Field("stp.protocol", "Protocol Identifier", d.FtUint16, d.WithBase(d.BaseHex))
	hfSTPVersion = protoSTP.Field("stp.version", "Protocol Version Identifier", d.FtUint8)
	hfSTPType    = protoSTP.Field("stp.type", "BPDU Type", d.FtUint8, d.WithBase(d.BaseHex), d.WithVS(stpTypes))
	hfSTPFlags   = protoSTP.Field("stp.flags", "BPDU flags", d.FtUint8, d.WithBase(d.BaseHex))
	hfSTPRootPri = protoSTP.Field("stp.root.prio", "Root Bridge Priority", d.FtUint16)
	hfSTPRootMAC = protoSTP.Field("stp.root.hw", "Root Bridge System ID", d.FtEther)
	hfSTPCost    = protoSTP.Field("stp.root.cost", "Root Path Cost", d.FtUint32)
	hfSTPBrPri   = protoSTP.Field("stp.bridge.prio", "Bridge Priority", d.FtUint16)
	hfSTPBrMAC   = protoSTP.Field("stp.bridge.hw", "Bridge System ID", d.FtEther)
	hfSTPPort    = protoSTP.Field("stp.port", "Port identifier", d.FtUint16, d.WithBase(d.BaseHex))
	hfSTPAge     = protoSTP.Field("stp.msg_age", "Message Age", d.FtFloat)
	hfSTPMax     = protoSTP.Field("stp.max_age", "Max Age", d.FtFloat)
	hfSTPHello   = protoSTP.Field("stp.hello", "Hello Time", d.FtFloat)
	hfSTPFwd     = protoSTP.Field("stp.forward", "Forward Delay", d.FtFloat)
	stpHandle    = d.RegisterHandle("stp", d.NewHandle(protoSTP, dissectSTP))
)

func init() { LLCSAPTable.Add(0x42, stpHandle) }

func dissectSTP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 4 {
		return 0
	}
	st := tree.AddProtocol(protoSTP, tvb, 0, -1)
	pi.SetProtocol("STP")
	st.AddUint(hfSTPProto, tvb, 0, 2)
	st.AddUint(hfSTPVersion, tvb, 2, 1)
	_, typ := st.AddUint(hfSTPType, tvb, 3, 1)
	if typ == 0x80 {
		pi.SetInfo("Topology Change Notification")
		return tvb.Len()
	}
	if tvb.Len() < 35 {
		return tvb.Len()
	}
	st.AddUint(hfSTPFlags, tvb, 4, 1)
	st.AddValue(hfSTPRootPri, tvb, 5, 2, d.UintValue(d.FtUint16, uint64(tvb.U16(5)&0xf000)))
	st.AddBytes(hfSTPRootMAC, tvb, 7, 6)
	st.AddUint(hfSTPCost, tvb, 13, 4)
	st.AddValue(hfSTPBrPri, tvb, 17, 2, d.UintValue(d.FtUint16, uint64(tvb.U16(17)&0xf000)))
	st.AddBytes(hfSTPBrMAC, tvb, 19, 6)
	st.AddUint(hfSTPPort, tvb, 25, 2)
	for i, f := range []*d.FieldDef{hfSTPAge, hfSTPMax, hfSTPHello, hfSTPFwd} {
		st.AddValue(f, tvb, 27+2*i, 2, d.FloatValue(d.FtFloat, float64(tvb.U16(27+2*i))/256))
	}
	rm := tvb.Bytes(7, 6)
	pi.SetInfo(fmt.Sprintf("%s. Root = %d/%02x:%02x:%02x:%02x:%02x:%02x  Cost = %d  Port = 0x%04x", map[uint64]string{0: "Conf", 2: "RST"}[typ],
		tvb.U16(5)&0xf000, rm[0], rm[1], rm[2], rm[3], rm[4], rm[5], tvb.U32(13), tvb.U16(25)))
	return tvb.Len()
}

// ---------------- LLDP ----------------

var (
	lldpTLVs = map[uint64]string{0: "End of LLDPDU", 1: "Chassis Id", 2: "Port Id", 3: "Time To Live", 4: "Port Description",
		5: "System Name", 6: "System Description", 7: "System Capabilities", 8: "Management Address", 127: "Organization Specific"}
	protoLLDP   = d.RegisterProto("Link Layer Discovery Protocol", "LLDP", "lldp")
	hfLLDPType  = protoLLDP.Field("lldp.tlv.type", "TLV Type", d.FtUint16, d.WithMask(0xfe00), d.WithParentBits(16), d.WithVS(lldpTLVs))
	hfLLDPLen   = protoLLDP.Field("lldp.tlv.len", "TLV Length", d.FtUint16, d.WithMask(0x01ff), d.WithParentBits(16))
	hfLLDPChas  = protoLLDP.Field("lldp.chassis.id", "Chassis Id", d.FtString)
	hfLLDPChasM = protoLLDP.Field("lldp.chassis.id.mac", "Chassis Id", d.FtEther)
	hfLLDPPort  = protoLLDP.Field("lldp.port.id", "Port Id", d.FtString)
	hfLLDPTTL   = protoLLDP.Field("lldp.time_to_live", "Seconds", d.FtUint16)
	hfLLDPDesc  = protoLLDP.Field("lldp.port.desc", "Port Description", d.FtString)
	hfLLDPName  = protoLLDP.Field("lldp.tlv.system.name", "System Name", d.FtString)
	hfLLDPSys   = protoLLDP.Field("lldp.tlv.system.desc", "System Description", d.FtString)
	lldpHandle  = d.RegisterHandle("lldp", d.NewHandle(protoLLDP, dissectLLDP))
)

var lldpChassisAbbr = map[byte]string{1: "CC", 2: "IA", 3: "PC", 4: "MA", 5: "NA", 6: "IN", 7: "LA"}
var lldpPortAbbr = map[byte]string{1: "IA", 2: "PC", 3: "MA", 4: "NA", 5: "IN", 6: "AC", 7: "LA"}

func init() { EtherTypeTable.Add(0x88cc, lldpHandle) }

func dissectLLDP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	lt := tree.AddProtocol(protoLLDP, tvb, 0, -1)
	pi.SetProtocol("LLDP")
	var chassis, port, sysName string
	var chassisSub, portSub byte
	var ttl uint64
	for off := 0; tvb.Remaining(off) >= 2; {
		h := tvb.U16(off)
		typ, l := uint64(h>>9), int(h&0x1ff)
		tn := lt.AddText(tvb, off, 2+l, "%s", orDefault(lldpTLVs[typ], "TLV"))
		tn.AddBits(hfLLDPType, tvb, off, 2, uint64(h))
		tn.AddBits(hfLLDPLen, tvb, off, 2, uint64(h))
		v := off + 2
		switch typ {
		case 1:
			sub := tvb.U8(v)
			chassisSub = sub
			if sub == 4 && l == 7 {
				tn.AddBytes(hfLLDPChasM, tvb, v+1, 6)
				b := tvb.Bytes(v+1, 6)
				chassis = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
			} else {
				_, chassis = tn.AddString(hfLLDPChas, tvb, v+1, l-1)
			}
			tn.SetText("Chassis Subtype = %d, Id: %s", sub, chassis)
		case 2:
			portSub = tvb.U8(v)
			_, port = tn.AddString(hfLLDPPort, tvb, v+1, l-1)
			tn.SetText("Port Subtype = %d, Id: %s", tvb.U8(v), port)
		case 3:
			_, ttl = tn.AddUint(hfLLDPTTL, tvb, v, 2)
		case 4:
			tn.AddString(hfLLDPDesc, tvb, v, l)
		case 5:
			_, s := tn.AddString(hfLLDPName, tvb, v, l)
			sysName = s
			tn.SetText("System Name = %s", s)
		case 6:
			tn.AddString(hfLLDPSys, tvb, v, l)
		}
		off += 2 + l
		if typ == 0 {
			break
		}
	}
	info := fmt.Sprintf("%s/%s %s/%s %d", lldpChassisAbbr[chassisSub], chassis, lldpPortAbbr[portSub], port, ttl)
	if sysName != "" {
		info += " SysN=" + sysName
	}
	pi.SetInfo(info)
	return tvb.Len()
}

// ---------------- CDP ----------------

var (
	cdpTLVs = map[uint64]string{1: "Device ID", 2: "Addresses", 3: "Port ID", 4: "Capabilities", 5: "Software version", 6: "Platform",
		9: "VTP Management Domain", 10: "Native VLAN", 11: "Duplex", 0x16: "Management Addresses"}
	protoCDP  = d.RegisterProto("Cisco Discovery Protocol", "CDP", "cdp")
	hfCDPVer  = protoCDP.Field("cdp.version", "Version", d.FtUint8)
	hfCDPTTL  = protoCDP.Field("cdp.ttl", "TTL", d.FtUint8)
	hfCDPSum  = protoCDP.Field("cdp.checksum", "Checksum", d.FtUint16, d.WithBase(d.BaseHex))
	hfCDPType = protoCDP.Field("cdp.tlv.type", "Type", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(cdpTLVs))
	hfCDPLen  = protoCDP.Field("cdp.tlv.len", "Length", d.FtUint16)
	hfCDPDev  = protoCDP.Field("cdp.deviceid", "Device ID", d.FtString)
	hfCDPPort = protoCDP.Field("cdp.portid", "Sent through Interface", d.FtString)
	hfCDPSW   = protoCDP.Field("cdp.software_version", "Software Version", d.FtString)
	hfCDPPlat = protoCDP.Field("cdp.platform", "Platform", d.FtString)
	cdpHandle = d.RegisterHandle("cdp", d.NewHandle(protoCDP, dissectCDP))
)

func init() { LLCCiscoPID.Add(0x2000, cdpHandle) }

func dissectCDP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 4 {
		return 0
	}
	ct := tree.AddProtocol(protoCDP, tvb, 0, -1)
	pi.SetProtocol("CDP")
	ct.AddUint(hfCDPVer, tvb, 0, 1)
	ct.AddUint(hfCDPTTL, tvb, 1, 1)
	ct.AddUint(hfCDPSum, tvb, 2, 2)
	var dev, port string
	for off := 4; tvb.Remaining(off) >= 4; {
		typ, l := uint64(tvb.U16(off)), int(tvb.U16(off+2))
		if l < 4 || off+l > tvb.Len() {
			break
		}
		tn := ct.AddText(tvb, off, l, "%s", orDefault(cdpTLVs[typ], fmt.Sprintf("Type 0x%04x", typ)))
		tn.AddUint(hfCDPType, tvb, off, 2)
		tn.AddUint(hfCDPLen, tvb, off+2, 2)
		switch typ {
		case 1:
			_, dev = tn.AddString(hfCDPDev, tvb, off+4, l-4)
		case 3:
			_, port = tn.AddString(hfCDPPort, tvb, off+4, l-4)
		case 5:
			tn.AddString(hfCDPSW, tvb, off+4, l-4)
		case 6:
			tn.AddString(hfCDPPlat, tvb, off+4, l-4)
		}
		off += l
	}
	pi.SetInfo(fmt.Sprintf("Device ID: %s  Port ID: %s", dev, port))
	return tvb.Len()
}

// ---------------- SNMP ----------------

var (
	snmpPDUs = map[uint64]string{0: "get-request", 1: "get-next-request", 2: "get-response", 3: "set-request", 4: "trap", 5: "get-bulk-request",
		6: "inform-request", 7: "snmpV2-trap", 8: "report"}
	protoSNMP    = d.RegisterProto("Simple Network Management Protocol", "SNMP", "snmp")
	hfSNMPVer    = protoSNMP.Field("snmp.version", "version", d.FtInt32, d.WithVS(map[uint64]string{0: "version-1", 1: "v2c", 3: "version-3"}))
	hfSNMPComm   = protoSNMP.Field("snmp.community", "community", d.FtString)
	hfSNMPReqID  = protoSNMP.Field("snmp.request_id", "request-id", d.FtInt32)
	hfSNMPErrSt  = protoSNMP.Field("snmp.error_status", "error-status", d.FtInt32)
	hfSNMPErrIdx = protoSNMP.Field("snmp.error_index", "error-index", d.FtInt32)
	hfSNMPName   = protoSNMP.Field("snmp.name", "Object Name", d.FtString)
	hfSNMPValue  = protoSNMP.Field("snmp.value.string", "Value", d.FtString)
	hfSNMPInt    = protoSNMP.Field("snmp.value.int", "Value", d.FtInt64)
	hfSNMPData   = protoSNMP.Field("snmp.data", "data", d.FtUint8, d.WithVS(snmpPDUs))
	snmpHandle   = d.RegisterHandle("snmp", d.NewHandle(protoSNMP, dissectSNMP))
)

func init() {
	UDPPortTable.Add(161, snmpHandle)
	UDPPortTable.Add(162, snmpHandle)
}

type ber struct {
	tag    byte
	off    int // value offset in tvb
	length int
	next   int
}

func berRead(t *d.Tvb, off int) (ber, bool) {
	if !t.Has(off, 2) {
		return ber{}, false
	}
	b := ber{tag: t.U8(off)}
	l := int(t.U8(off + 1))
	p := off + 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n > 4 || !t.Has(p, n) {
			return ber{}, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(t.U8(p+i))
		}
		p += n
	}
	if !t.Has(p, l) {
		return ber{}, false
	}
	b.off, b.length, b.next = p, l, p+l
	return b, true
}

func berInt(t *d.Tvb, b ber) int64 {
	var v int64
	if b.length > 0 && t.U8(b.off)&0x80 != 0 {
		v = -1
	}
	for i := 0; i < b.length && i < 8; i++ {
		v = v<<8 | int64(t.U8(b.off+i))
	}
	return v
}

func berOID(t *d.Tvb, b ber) string {
	if b.length == 0 {
		return ""
	}
	first := t.U8(b.off)
	parts := []string{fmt.Sprint(first / 40), fmt.Sprint(first % 40)}
	var v uint64
	for i := 1; i < b.length; i++ {
		c := t.U8(b.off + i)
		v = v<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			parts = append(parts, fmt.Sprint(v))
			v = 0
		}
	}
	return strings.Join(parts, ".")
}

func dissectSNMP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	top, ok := berRead(tvb, 0)
	if !ok || top.tag != 0x30 {
		return 0
	}
	ver, ok := berRead(tvb, top.off)
	if !ok || ver.tag != 2 {
		return 0
	}
	st := tree.AddProtocol(protoSNMP, tvb, 0, -1)
	pi.SetProtocol("SNMP")
	v := berInt(tvb, ver)
	st.AddValue(hfSNMPVer, tvb, ver.off, ver.length, d.IntValue(d.FtInt32, v))
	if v == 3 {
		pi.SetInfo("SNMPv3 message")
		return tvb.Len()
	}
	comm, ok := berRead(tvb, ver.next)
	if !ok {
		return tvb.Len()
	}
	st.AddString(hfSNMPComm, tvb, comm.off, comm.length)
	pdu, ok := berRead(tvb, comm.next)
	if !ok {
		return tvb.Len()
	}
	kind := uint64(pdu.tag & 0x1f)
	st.AddValue(hfSNMPData, tvb, pdu.off, 0, d.UintValue(d.FtUint8, kind))
	info := orDefault(snmpPDUs[kind], "pdu")
	p := pdu.off
	var items []string
	if kind != 4 {
		rid, _ := berRead(tvb, p)
		st.AddValue(hfSNMPReqID, tvb, rid.off, rid.length, d.IntValue(d.FtInt32, berInt(tvb, rid)))
		es, _ := berRead(tvb, rid.next)
		st.AddValue(hfSNMPErrSt, tvb, es.off, es.length, d.IntValue(d.FtInt32, berInt(tvb, es)))
		ei, _ := berRead(tvb, es.next)
		st.AddValue(hfSNMPErrIdx, tvb, ei.off, ei.length, d.IntValue(d.FtInt32, berInt(tvb, ei)))
		vbs, ok := berRead(tvb, ei.next)
		if ok {
			for q := vbs.off; q < vbs.next; {
				vb, ok := berRead(tvb, q)
				if !ok {
					break
				}
				name, ok := berRead(tvb, vb.off)
				if ok && name.tag == 6 {
					oid := berOID(tvb, name)
					st.AddValue(hfSNMPName, tvb, name.off, name.length, d.StringValue(oid))
					items = append(items, oid)
					if val, ok := berRead(tvb, name.next); ok {
						switch val.tag {
						case 4:
							st.AddString(hfSNMPValue, tvb, val.off, val.length)
						case 2, 0x41, 0x42, 0x43, 0x46:
							st.AddValue(hfSNMPInt, tvb, val.off, val.length, d.IntValue(d.FtInt64, berInt(tvb, val)))
						}
					}
				}
				q = vb.next
			}
		}
	}
	if len(items) > 0 {
		info += " " + strings.Join(items, " ")
	}
	pi.SetInfo(info)
	return tvb.Len()
}

// ---------------- SSDP / NBNS ----------------

var (
	protoNBNS   = d.RegisterProto("NetBIOS Name Service", "NBNS", "nbns")
	hfNBNSID    = protoNBNS.Field("nbns.id", "Transaction ID", d.FtUint16, d.WithBase(d.BaseHex))
	hfNBNSFlags = protoNBNS.Field("nbns.flags", "Flags", d.FtUint16, d.WithBase(d.BaseHex))
	hfNBNSName  = protoNBNS.Field("nbns.name", "Name", d.FtString)
	hfNBNSType  = protoNBNS.Field("nbns.type", "Type", d.FtUint16, d.WithVS(map[uint64]string{0x20: "NB", 0x21: "NBSTAT"}))
	nbnsHandle  = d.RegisterHandle("nbns", d.NewHandle(protoNBNS, dissectNBNS))
)

func init() {
	UDPPortTable.Add(137, nbnsHandle)
	UDPPortTable.Add(1900, d.NewHandle(protoHTTP, DissectHTTP))
}

func dissectNBNS(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 12 {
		return 0
	}
	nt := tree.AddProtocol(protoNBNS, tvb, 0, -1)
	pi.SetProtocol("NBNS")
	nt.AddUint(hfNBNSID, tvb, 0, 2)
	flags := tvb.U16(2)
	nt.AddUint(hfNBNSFlags, tvb, 2, 2)
	qd := tvb.U16(4)
	name := ""
	if qd > 0 && tvb.Has(12, 34) && tvb.U8(12) == 0x20 {
		var b []byte
		for i := 0; i < 16; i++ {
			hi, lo := tvb.U8(13+2*i)-'A', tvb.U8(14+2*i)-'A'
			b = append(b, hi<<4|lo)
		}
		suffix := b[15]
		name = fmt.Sprintf("%s<%02x>", strings.TrimRight(string(b[:15]), " \x00"), suffix)
		nt.AddValue(hfNBNSName, tvb, 12, 34, d.StringValue(name))
		nt.AddUint(hfNBNSType, tvb, 46, 2)
	}
	kind := "Name query"
	if flags&0x8000 != 0 {
		kind = "Name query response"
	}
	if (flags>>11)&0xf == 5 {
		kind = "Registration"
	}
	pi.SetInfo(fmt.Sprintf("%s NB %s", kind, name))
	return tvb.Len()
}
