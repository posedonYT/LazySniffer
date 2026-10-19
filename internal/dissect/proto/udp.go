package proto

import (
	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	protoUDP       = d.RegisterProto("User Datagram Protocol", "UDP", "udp")
	hfUDPSrcPort   = protoUDP.Field("udp.srcport", "Source Port", d.FtUint16)
	hfUDPDstPort   = protoUDP.Field("udp.dstport", "Destination Port", d.FtUint16)
	hfUDPPort      = protoUDP.Field("udp.port", "Source or Destination Port", d.FtUint16)
	hfUDPLength    = protoUDP.Field("udp.length", "Length", d.FtUint16)
	hfUDPChecksum  = protoUDP.Field("udp.checksum", "Checksum", d.FtUint16, d.WithBase(d.BaseHex))
	hfUDPCkStatus  = protoUDP.Field("udp.checksum.status", "Checksum Status", d.FtUint8, d.WithVS(checksumStatus), d.WithBase(d.BaseNone))
	hfUDPStream    = protoUDP.Field("udp.stream", "Stream index", d.FtUint32)
	hfUDPTimeRel   = protoUDP.Field("udp.time_relative", "Time since first frame", d.FtRelTime)
	hfUDPTimeDelta = protoUDP.Field("udp.time_delta", "Time since previous frame", d.FtRelTime)
	hfUDPPayload   = protoUDP.Field("udp.payload", "UDP payload", d.FtBytes)
	eiUDPBadLen    = protoUDP.Expert("udp.length.bad", d.GroupMalformed, d.SevError, "Bad length value")
	eiUDPBadLenZ   = protoUDP.Expert("udp.length.bad_zero", d.GroupProtocol, d.SevWarn, "Length is zero but payload < 65536")

	// UDPPortTable dispatches UDP payloads by port.
	UDPPortTable = d.Table("udp.port")
	// UDPHeur holds heuristic dissectors for UDP payloads.
	UDPHeur = d.Heur("udp")
)

func init() {
	IPProtoTable.Add(17, d.NewHandle(protoUDP, dissectUDP))
}

type udpConv struct{ lastTS int64 }

var protoUDPFrames = d.RegisterProto("UDP per-frame state", "_udpstate", "_ws.udpstate")

func udpFrames(s *d.Session) *d.FrameTable[udpFrame] {
	return d.SessionTable[udpFrame](s, protoUDPFrames)
}

type udpFrame struct {
	stream    uint32
	timeRel   int64
	timeDelta int64
}

func dissectUDP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	sport, dport := uint32(tvb.U16(0)), uint32(tvb.U16(2))
	ulen := int(tvb.U16(4))
	ut := tree.AddProtocol(protoUDP, tvb, 0, 8)
	ut.SetText("User Datagram Protocol, Src Port: %d, Dst Port: %d", sport, dport)
	addPort(ut, hfUDPSrcPort, tvb, 0, sport, "udp")
	addPort(ut, hfUDPDstPort, tvb, 2, dport, "udp")
	ut.AddHidden(hfUDPPort, tvb, 0, 2, d.Value{U: uint64(sport)})
	ut.AddHidden(hfUDPPort, tvb, 2, 2, d.Value{U: uint64(dport)})
	ln, _ := ut.AddUint(hfUDPLength, tvb, 4, 2)
	if pi.InErrorPkt {
		return tvb.Len()
	}
	pi.SetProtocol("UDP")
	pi.PortType, pi.SrcPort, pi.DstPort = d.PortUDP, sport, dport
	reported := tvb.Reported()
	if ulen == 0 && reported >= 8 {
		ln.AddExpert(eiUDPBadLenZ, "")
		ulen = reported
	}
	if ulen < 8 || ulen > reported {
		ln.AppendText(" (bogus, payload length %d)", reported)
		ln.AddExpert(eiUDPBadLen, "Bad length value %d > IP payload length", ulen)
		ulen = reported
		if ulen < 8 {
			return tvb.Len()
		}
	}
	ckn, ck := ut.AddUint(hfUDPChecksum, tvb, 6, 2)
	if ck == 0 {
		ckn.SetText("Checksum: 0x0000 [zero-value ignored]")
		ut.AddGenerated(hfUDPCkStatus, d.Value{U: 3})
	} else {
		ckn.AppendText(" [unverified]")
		ut.AddGenerated(hfUDPCkStatus, d.Value{U: 2})
	}

	sess := pi.Sess
	var fd *udpFrame
	if pi.Visited {
		if v, ok := udpFrames(sess).Get(pi.Num); ok {
			fd = &v
		}
	}
	if fd == nil {
		fd = &udpFrame{}
		if c := sess.Conversation(pi, d.ConvUDP, pi.Src, pi.Dst, sport, dport); c != nil {
			st, _ := c.Data(protoUDP).(*udpConv)
			if st == nil {
				st = &udpConv{lastTS: pi.TS}
				if !pi.Visited {
					c.SetData(protoUDP, st)
				}
			}
			fd.stream = c.Index
			fd.timeRel = pi.TS - c.FirstTS
			fd.timeDelta = pi.TS - st.lastTS
			st.lastTS = pi.TS
		}
		if !pi.Visited {
			udpFrames(sess).Put(pi.Num, *fd)
		}
	}
	pi.Conv = sess.FindConversation(d.ConvUDP, pi.Src, pi.Dst, sport, dport)
	ut.AddGenerated(hfUDPStream, d.Value{U: uint64(fd.stream)})
	ts := ut.AddText(nil, 0, 0, "[Timestamps]")
	ts.AddGenerated(hfUDPTimeRel, d.RelTimeValue(fd.timeRel)).
		SetText("[Time since first frame: %s seconds]", d.FormatRelTime(fd.timeRel))
	ts.AddGenerated(hfUDPTimeDelta, d.RelTimeValue(fd.timeDelta)).
		SetText("[Time since previous frame: %s seconds]", d.FormatRelTime(fd.timeDelta))

	plen := ulen - 8
	pi.SetInfof("%s → %s Len=%d", portLabel(sport, "udp"), portLabel(dport, "udp"), plen)
	if plen > 0 && tvb.Remaining(8) > 0 {
		payload := tvb.Sub(8, plen)
		pn, _ := ut.AddBytes(hfUDPPayload, tvb, 8, payload.Len())
		pn.SetText("UDP payload (%d byte%s)", plen, plural(plen))
		dispatchPorts(UDPPortTable, UDPHeur, payload, pi, tree, sport, dport)
	}
	return ulen
}

// PortResolver, when set, returns a service name for a port ("https").
var PortResolver func(port uint32, transport string) string

// portLabel renders a port for Info columns: "443" or "https(443)".
func portLabel(p uint32, transport string) string {
	if PortResolver != nil {
		if s := PortResolver(p, transport); s != "" {
			return s + "(" + d.PortString(p) + ")"
		}
	}
	return d.PortString(p)
}

func addPort(tree *d.Node, hf *d.FieldDef, tvb *d.Tvb, off int, port uint32, transport string) {
	n, _ := tree.AddUint(hf, tvb, off, 2)
	if PortResolver != nil {
		if s := PortResolver(port, transport); s != "" {
			n.SetText("%s: %s (%d)", hf.Name, s, port)
		}
	}
}
