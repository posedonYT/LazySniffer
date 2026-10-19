package proto

import (
	"fmt"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

// ---- IGMP ----

var (
	igmpTypes = map[uint64]string{0x11: "Membership Query", 0x12: "Membership Report", 0x16: "Membership Report",
		0x17: "Leave Group", 0x22: "Membership Report", 0x13: "DVMRP", 0x14: "PIM v1", 0x1e: "Multicast Traceroute Response",
		0x1f: "Multicast Traceroute", 0x30: "Multicast Router Advertisement", 0x31: "Multicast Router Solicitation",
		0x32: "Multicast Router Termination"}
	igmpRecTypes = map[uint64]string{1: "Mode Is Include", 2: "Mode Is Exclude", 3: "Change To Include Mode",
		4: "Change To Exclude Mode", 5: "Allow New Sources", 6: "Block Old Sources"}
	protoIGMP     = d.RegisterProto("Internet Group Management Protocol", "IGMP", "igmp")
	hfIGMPVersion = protoIGMP.Field("igmp.version", "IGMP Version", d.FtUint8)
	hfIGMPType    = protoIGMP.Field("igmp.type", "Type", d.FtUint8, d.WithBase(d.BaseHex), d.WithVS(igmpTypes))
	hfIGMPMaxResp = protoIGMP.Field("igmp.max_resp", "Max Resp Time", d.FtUint8)
	hfIGMPCksum   = protoIGMP.Field("igmp.checksum", "Checksum", d.FtUint16, d.WithBase(d.BaseHex))
	hfIGMPCkStat  = protoIGMP.Field("igmp.checksum.status", "Checksum Status", d.FtUint8, d.WithVS(checksumStatus), d.WithBase(d.BaseNone))
	hfIGMPMaddr   = protoIGMP.Field("igmp.maddr", "Multicast Address", d.FtIPv4)
	hfIGMPSFlag   = protoIGMP.Field("igmp.s", "S", d.FtBool, d.WithMask(0x08), d.WithParentBits(8), d.WithTFS(&d.TrueFalse{True: "Suppress router side processing", False: "Do not suppress router side processing"}))
	hfIGMPQRV     = protoIGMP.Field("igmp.qrv", "QRV", d.FtUint8, d.WithMask(0x07))
	hfIGMPQQIC    = protoIGMP.Field("igmp.qqic", "QQIC", d.FtUint8)
	hfIGMPNumSrc  = protoIGMP.Field("igmp.num_src", "Num Src", d.FtUint16)
	hfIGMPSaddr   = protoIGMP.Field("igmp.saddr", "Source Address", d.FtIPv4)
	hfIGMPNumRecs = protoIGMP.Field("igmp.num_grp_recs", "Num Group Records", d.FtUint16)
	hfIGMPRecType = protoIGMP.Field("igmp.record_type", "Record Type", d.FtUint8, d.WithVS(igmpRecTypes))
	hfIGMPAuxLen  = protoIGMP.Field("igmp.aux_data_len", "Aux Data Len", d.FtUint8)
)

func init() {
	IPProtoTable.Add(2, d.NewHandle(protoIGMP, dissectIGMP))
}

func dissectIGMP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	typ := uint64(tvb.U8(0))
	it := tree.AddProtocol(protoIGMP, tvb, 0, -1)
	version := 2
	switch {
	case typ == 0x12:
		version = 1
	case typ == 0x22 || (typ == 0x11 && tvb.Len() >= 12):
		version = 3
	case typ == 0x11 && tvb.U8(1) == 0:
		version = 1
	}
	pi.SetProtocol(fmt.Sprintf("IGMPv%d", version))
	it.SetText("Internet Group Management Protocol")
	it.AddGenerated(hfIGMPVersion, d.Value{U: uint64(version)})
	it.AddUint(hfIGMPType, tvb, 0, 1)
	if version != 3 || typ == 0x11 {
		it.AddUint(hfIGMPMaxResp, tvb, 1, 1)
	}
	ckn, _ := it.AddUint(hfIGMPCksum, tvb, 2, 2)
	if tvb.Len() == tvb.Reported() && InetChecksum(tvb.Raw(), 0) == 0 {
		ckn.AppendText(" [correct]")
		it.AddGenerated(hfIGMPCkStat, d.Value{U: 1})
	} else if tvb.Len() == tvb.Reported() {
		ckn.AppendText(" [incorrect]")
		it.AddGenerated(hfIGMPCkStat, d.Value{U: 0})
	}
	info := igmpTypes[typ]
	switch typ {
	case 0x11, 0x12, 0x16, 0x17:
		_, g := it.AddIPv4(hfIGMPMaddr, tvb, 4)
		switch {
		case typ == 0x11 && g == 0:
			info += ", general"
		case typ == 0x11:
			info += ", specific for group " + d.FormatIPv4(g)
		case typ == 0x17:
			info += " " + d.FormatIPv4(g)
		default:
			info += " group " + d.FormatIPv4(g)
		}
		if version == 3 && typ == 0x11 {
			b8 := uint64(tvb.U8(8))
			it.AddBits(hfIGMPSFlag, tvb, 8, 1, b8)
			it.AddBits(hfIGMPQRV, tvb, 8, 1, b8)
			it.AddUint(hfIGMPQQIC, tvb, 9, 1)
			_, n := it.AddUint(hfIGMPNumSrc, tvb, 10, 2)
			for i := 0; i < int(n); i++ {
				it.AddIPv4(hfIGMPSaddr, tvb, 12+4*i)
			}
		}
	case 0x22:
		_, n := it.AddUint(hfIGMPNumRecs, tvb, 6, 2)
		off := 8
		var groups []string
		for i := 0; i < int(n); i++ {
			rt := uint64(tvb.U8(off))
			aux := int(tvb.U8(off+1)) * 4
			ns := int(tvb.U16(off + 2))
			g := tvb.U32(off + 4)
			rn := it.AddText(tvb, off, 8+4*ns+aux, "Group Record : %s  %s", d.FormatIPv4(g), igmpRecTypes[rt])
			rn.AddUint(hfIGMPRecType, tvb, off, 1)
			rn.AddUint(hfIGMPAuxLen, tvb, off+1, 1)
			rn.AddUint(hfIGMPNumSrc, tvb, off+2, 2)
			rn.AddIPv4(hfIGMPMaddr, tvb, off+4)
			for s := 0; s < ns; s++ {
				rn.AddIPv4(hfIGMPSaddr, tvb, off+8+4*s)
			}
			action := "Join"
			if (rt == 3 || rt == 1) && ns == 0 {
				action = "Leave"
			}
			groups = append(groups, fmt.Sprintf("%s group %s for any sources", action, d.FormatIPv4(g)))
			off += 8 + 4*ns + aux
		}
		if len(groups) > 0 {
			info += " / " + strings.Join(groups, " / ")
		}
	}
	pi.SetInfo(info)
	return tvb.Len()
}

// ---- SCTP ----

var (
	sctpChunkTypes = map[uint64]string{0: "DATA", 1: "INIT", 2: "INIT_ACK", 3: "SACK", 4: "HEARTBEAT",
		5: "HEARTBEAT_ACK", 6: "ABORT", 7: "SHUTDOWN", 8: "SHUTDOWN_ACK", 9: "ERROR", 10: "COOKIE_ECHO",
		11: "COOKIE_ACK", 12: "ECNE", 13: "CWR", 14: "SHUTDOWN_COMPLETE", 15: "AUTH", 64: "I_DATA",
		128: "ASCONF_ACK", 130: "RE_CONFIG", 132: "PAD", 192: "FORWARD_TSN", 193: "ASCONF", 194: "I_FORWARD_TSN"}
	sctpPPIs = map[uint64]string{0: "not specified", 3: "M3UA", 4: "SUA", 5: "M2UA", 18: "S1 Application Protocol (S1AP)",
		46: "Diameter", 47: "Diameter DTLS", 51: "WebRTC String", 53: "WebRTC Binary", 60: "NGAP", 61: "XwAP"}
	protoSCTP      = d.RegisterProto("Stream Control Transmission Protocol", "SCTP", "sctp")
	hfSCTPSrcPort  = protoSCTP.Field("sctp.srcport", "Source port", d.FtUint16)
	hfSCTPDstPort  = protoSCTP.Field("sctp.dstport", "Destination port", d.FtUint16)
	hfSCTPPort     = protoSCTP.Field("sctp.port", "Port", d.FtUint16)
	hfSCTPVTag     = protoSCTP.Field("sctp.verification_tag", "Verification tag", d.FtUint32, d.WithBase(d.BaseHex))
	hfSCTPChecksum = protoSCTP.Field("sctp.checksum", "Checksum", d.FtUint32, d.WithBase(d.BaseHex))
	hfSCTPAssoc    = protoSCTP.Field("sctp.assoc_index", "Association index", d.FtUint32)
	hfSCTPChunk    = protoSCTP.Field("sctp.chunk_type", "Chunk type", d.FtUint8, d.WithVS(sctpChunkTypes))
	hfSCTPChFlags  = protoSCTP.Field("sctp.chunk_flags", "Chunk flags", d.FtUint8, d.WithBase(d.BaseHex))
	hfSCTPChLen    = protoSCTP.Field("sctp.chunk_length", "Chunk length", d.FtUint16)
	hfSCTPTSN      = protoSCTP.Field("sctp.data_tsn", "Transmission sequence number (relative)", d.FtUint32)
	hfSCTPSID      = protoSCTP.Field("sctp.data_sid", "Stream identifier", d.FtUint16, d.WithBase(d.BaseHex))
	hfSCTPSSN      = protoSCTP.Field("sctp.data_ssn", "Stream sequence number", d.FtUint16)
	hfSCTPPPI      = protoSCTP.Field("sctp.data_payload_proto_id", "Payload protocol identifier", d.FtUint32, d.WithVS(sctpPPIs))
	hfSCTPEBit     = protoSCTP.Field("sctp.data_e_bit", "E-Bit", d.FtBool, d.WithMask(0x01), d.WithParentBits(8), d.WithTFS(&d.TrueFalse{True: "Last segment", False: "Not the last segment"}))
	hfSCTPBBit     = protoSCTP.Field("sctp.data_b_bit", "B-Bit", d.FtBool, d.WithMask(0x02), d.WithParentBits(8), d.WithTFS(&d.TrueFalse{True: "First segment", False: "Subsequent segment"}))
	hfSCTPUBit     = protoSCTP.Field("sctp.data_u_bit", "U-Bit", d.FtBool, d.WithMask(0x04), d.WithParentBits(8), d.WithTFS(&d.TrueFalse{True: "Unordered delivery", False: "Ordered delivery"}))
	hfSCTPInitTag  = protoSCTP.Field("sctp.init_initiate_tag", "Initiate tag", d.FtUint32, d.WithBase(d.BaseHex))
	hfSCTPInitRwnd = protoSCTP.Field("sctp.init_credit", "Advertised receiver window credit (a_rwnd)", d.FtUint32)
	hfSCTPInitOS   = protoSCTP.Field("sctp.init_nr_out_streams", "Number of outbound streams", d.FtUint16)
	hfSCTPInitIS   = protoSCTP.Field("sctp.init_nr_in_streams", "Number of inbound streams", d.FtUint16)
	hfSCTPInitTSN  = protoSCTP.Field("sctp.init_initial_tsn", "Initial TSN", d.FtUint32)
	hfSCTPSackTSN  = protoSCTP.Field("sctp.sack_cumulative_tsn_ack", "Cumulative TSN ACK", d.FtUint32)
	hfSCTPSackRwnd = protoSCTP.Field("sctp.sack_a_rwnd", "Advertised receiver window credit (a_rwnd)", d.FtUint32)
	hfSCTPChValue  = protoSCTP.Field("sctp.chunk_value", "Chunk value", d.FtBytes)
	// SCTPPPITable dispatches DATA chunk payloads by PPID.
	SCTPPPITable = d.Table("sctp.ppi")
	// SCTPPortTable dispatches DATA chunk payloads by port.
	SCTPPortTable = d.Table("sctp.port")
)

func init() {
	IPProtoTable.Add(132, d.NewHandle(protoSCTP, dissectSCTP))
}

func dissectSCTP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	sport, dport := uint32(tvb.U16(0)), uint32(tvb.U16(2))
	st := tree.AddProtocol(protoSCTP, tvb, 0, -1)
	st.SetText("Stream Control Transmission Protocol, Src Port: %d, Dst Port: %d", sport, dport)
	addPort(st, hfSCTPSrcPort, tvb, 0, sport, "sctp")
	addPort(st, hfSCTPDstPort, tvb, 2, dport, "sctp")
	st.AddHidden(hfSCTPPort, tvb, 0, 2, d.Value{U: uint64(sport)})
	st.AddHidden(hfSCTPPort, tvb, 2, 2, d.Value{U: uint64(dport)})
	if pi.InErrorPkt {
		return tvb.Len()
	}
	pi.SetProtocol("SCTP")
	pi.PortType, pi.SrcPort, pi.DstPort = d.PortSCTP, sport, dport
	st.AddUint(hfSCTPVTag, tvb, 4, 4)
	ckn, _ := st.AddUint(hfSCTPChecksum, tvb, 8, 4)
	ckn.AppendText(" [unverified]")
	if c := pi.Sess.Conversation(pi, d.ConvSCTP, pi.Src, pi.Dst, sport, dport); c != nil {
		pi.Conv = c
		st.AddGenerated(hfSCTPAssoc, d.Value{U: uint64(c.Index)})
	}
	var names []string
	off := 12
	for tvb.Remaining(off) >= 4 {
		typ := uint64(tvb.U8(off))
		flags := uint64(tvb.U8(off + 1))
		l := int(tvb.U16(off + 2))
		if l < 4 {
			break
		}
		name := sctpChunkTypes[typ]
		if name == "" {
			name = fmt.Sprintf("UNKNOWN(%d)", typ)
		}
		names = append(names, name)
		ct := st.AddText(tvb, off, min(l, tvb.Remaining(off)), "%s chunk", name)
		ct.AddUint(hfSCTPChunk, tvb, off, 1)
		fn, _ := ct.AddUint(hfSCTPChFlags, tvb, off+1, 1)
		ct.AddUint(hfSCTPChLen, tvb, off+2, 2)
		body := off + 4
		switch typ {
		case 0:
			fn.AddBits(hfSCTPEBit, tvb, off+1, 1, flags)
			fn.AddBits(hfSCTPBBit, tvb, off+1, 1, flags)
			fn.AddBits(hfSCTPUBit, tvb, off+1, 1, flags)
			_, tsn := ct.AddUint(hfSCTPTSN, tvb, body, 4)
			_, sid := ct.AddUint(hfSCTPSID, tvb, body+4, 2)
			ct.AddUint(hfSCTPSSN, tvb, body+6, 2)
			_, ppi := ct.AddUint(hfSCTPPPI, tvb, body+8, 4)
			ct.SetText("DATA chunk (ordered, complete segment, TSN: %d, SID: %d, PPID: %d, payload length: %d bytes)", tsn, sid, ppi, l-16)
			if l > 16 {
				payload := tvb.Sub(body+12, min(l-16, tvb.Remaining(body+12)))
				if _, ok := SCTPPPITable.Try(ppi, payload, pi, tree); !ok {
					dispatchPorts(SCTPPortTable, nil, payload, pi, tree, sport, dport)
				}
			}
		case 1, 2:
			ct.AddUint(hfSCTPInitTag, tvb, body, 4)
			ct.AddUint(hfSCTPInitRwnd, tvb, body+4, 4)
			ct.AddUint(hfSCTPInitOS, tvb, body+8, 2)
			ct.AddUint(hfSCTPInitIS, tvb, body+10, 2)
			ct.AddUint(hfSCTPInitTSN, tvb, body+12, 4)
		case 3:
			ct.AddUint(hfSCTPSackTSN, tvb, body, 4)
			ct.AddUint(hfSCTPSackRwnd, tvb, body+4, 4)
		default:
			if l > 4 && tvb.Has(body, l-4) {
				ct.AddBytes(hfSCTPChValue, tvb, body, l-4)
			}
		}
		off += (l + 3) &^ 3
	}
	if len(names) > 0 && !strings.Contains(pi.Protocol(), "SCTP") {
		return tvb.Len()
	}
	pi.SetInfo(strings.Join(names, " "))
	return tvb.Len()
}
