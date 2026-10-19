package proto

import (
	"fmt"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	tcpOptKinds = map[uint64]string{0: "End of Option List (EOL)", 1: "No-Operation (NOP)", 2: "Maximum Segment Size",
		3: "Window Scale", 4: "SACK Permitted", 5: "SACK", 6: "Echo", 7: "Echo Reply", 8: "Time Stamp Option",
		19: "TCP MD5 signature", 27: "Quick-Start Response", 28: "User Timeout", 29: "TCP Authentication Option",
		30: "Multipath TCP", 34: "TCP Fast Open Cookie", 69: "Encryption Negotiation (TCP-ENO)",
		253: "RFC3692-style Experiment 1", 254: "RFC3692-style Experiment 2"}

	protoTCP        = d.RegisterProto("Transmission Control Protocol", "TCP", "tcp")
	hfTCPSrcPort    = protoTCP.Field("tcp.srcport", "Source Port", d.FtUint16)
	hfTCPDstPort    = protoTCP.Field("tcp.dstport", "Destination Port", d.FtUint16)
	hfTCPPort       = protoTCP.Field("tcp.port", "Source or Destination Port", d.FtUint16)
	hfTCPStream     = protoTCP.Field("tcp.stream", "Stream index", d.FtUint32)
	hfTCPLen        = protoTCP.Field("tcp.len", "TCP Segment Len", d.FtUint32)
	hfTCPSeq        = protoTCP.Field("tcp.seq", "Sequence Number", d.FtUint32)
	hfTCPSeqRaw     = protoTCP.Field("tcp.seq_raw", "Sequence Number (raw)", d.FtUint32)
	hfTCPNxtSeq     = protoTCP.Field("tcp.nxtseq", "Next Sequence Number", d.FtUint32)
	hfTCPAck        = protoTCP.Field("tcp.ack", "Acknowledgment Number", d.FtUint32)
	hfTCPAckRaw     = protoTCP.Field("tcp.ack_raw", "Acknowledgment number (raw)", d.FtUint32)
	hfTCPHdrLen     = protoTCP.Field("tcp.hdr_len", "Header Length", d.FtUint8, d.WithMask(0xf0))
	hfTCPFlags      = protoTCP.Field("tcp.flags", "Flags", d.FtUint16, d.WithMask(0x0fff), d.WithBase(d.BaseHex))
	hfTCPFlagRes    = protoTCP.Field("tcp.flags.res", "Reserved", d.FtBool, d.WithMask(0xe00), d.WithParentBits(12), d.WithTFS(d.TFSSet))
	hfTCPFlagAE     = protoTCP.Field("tcp.flags.ae", "Accurate ECN", d.FtBool, d.WithMask(0x100), d.WithParentBits(12), d.WithTFS(d.TFSSet))
	hfTCPFlagCWR    = protoTCP.Field("tcp.flags.cwr", "Congestion Window Reduced", d.FtBool, d.WithMask(0x080), d.WithParentBits(12), d.WithTFS(d.TFSSet))
	hfTCPFlagECE    = protoTCP.Field("tcp.flags.ece", "ECN-Echo", d.FtBool, d.WithMask(0x040), d.WithParentBits(12), d.WithTFS(d.TFSSet))
	hfTCPFlagURG    = protoTCP.Field("tcp.flags.urg", "Urgent", d.FtBool, d.WithMask(0x020), d.WithParentBits(12), d.WithTFS(d.TFSSet))
	hfTCPFlagACK    = protoTCP.Field("tcp.flags.ack", "Acknowledgment", d.FtBool, d.WithMask(0x010), d.WithParentBits(12), d.WithTFS(d.TFSSet))
	hfTCPFlagPSH    = protoTCP.Field("tcp.flags.push", "Push", d.FtBool, d.WithMask(0x008), d.WithParentBits(12), d.WithTFS(d.TFSSet))
	hfTCPFlagRST    = protoTCP.Field("tcp.flags.reset", "Reset", d.FtBool, d.WithMask(0x004), d.WithParentBits(12), d.WithTFS(d.TFSSet))
	hfTCPFlagSYN    = protoTCP.Field("tcp.flags.syn", "Syn", d.FtBool, d.WithMask(0x002), d.WithParentBits(12), d.WithTFS(d.TFSSet))
	hfTCPFlagFIN    = protoTCP.Field("tcp.flags.fin", "Fin", d.FtBool, d.WithMask(0x001), d.WithParentBits(12), d.WithTFS(d.TFSSet))
	hfTCPFlagStr    = protoTCP.Field("tcp.flags.str", "TCP Flags", d.FtString)
	hfTCPWinVal     = protoTCP.Field("tcp.window_size_value", "Window", d.FtUint16)
	hfTCPWin        = protoTCP.Field("tcp.window_size", "Calculated window size", d.FtUint32)
	hfTCPWinScale   = protoTCP.Field("tcp.window_size_scalefactor", "Window size scaling factor", d.FtInt32)
	hfTCPChecksum   = protoTCP.Field("tcp.checksum", "Checksum", d.FtUint16, d.WithBase(d.BaseHex))
	hfTCPCkStatus   = protoTCP.Field("tcp.checksum.status", "Checksum Status", d.FtUint8, d.WithVS(checksumStatus), d.WithBase(d.BaseNone))
	hfTCPUrgent     = protoTCP.Field("tcp.urgent_pointer", "Urgent Pointer", d.FtUint16)
	hfTCPOptions    = protoTCP.Field("tcp.options", "TCP Options", d.FtBytes)
	hfTCPOptKind    = protoTCP.Field("tcp.option_kind", "Kind", d.FtUint8, d.WithVS(tcpOptKinds))
	hfTCPOptLen     = protoTCP.Field("tcp.option_len", "Length", d.FtUint8)
	hfTCPOptNOP     = protoTCP.Field("tcp.options.nop", "TCP Option - No-Operation (NOP)", d.FtBytes)
	hfTCPOptEOL     = protoTCP.Field("tcp.options.eol", "TCP Option - End of Option List (EOL)", d.FtBytes)
	hfTCPOptMSS     = protoTCP.Field("tcp.options.mss", "TCP Option - Maximum segment size", d.FtNone)
	hfTCPOptMSSVal  = protoTCP.Field("tcp.options.mss_val", "MSS Value", d.FtUint16)
	hfTCPOptWS      = protoTCP.Field("tcp.options.wscale", "TCP Option - Window scale", d.FtNone)
	hfTCPOptWSShift = protoTCP.Field("tcp.options.wscale.shift", "Shift count", d.FtUint8)
	hfTCPOptWSMult  = protoTCP.Field("tcp.options.wscale.multiplier", "Multiplier", d.FtUint16)
	hfTCPOptSACKP   = protoTCP.Field("tcp.options.sack_perm", "TCP Option - SACK permitted", d.FtNone)
	hfTCPOptSACK    = protoTCP.Field("tcp.options.sack", "TCP Option - SACK", d.FtNone)
	hfTCPOptSACKLE  = protoTCP.Field("tcp.options.sack_le", "left edge", d.FtUint32)
	hfTCPOptSACKRE  = protoTCP.Field("tcp.options.sack_re", "right edge", d.FtUint32)
	hfTCPOptSACKCnt = protoTCP.Field("tcp.options.sack.count", "TCP SACK Count", d.FtUint8)
	hfTCPOptTS      = protoTCP.Field("tcp.options.timestamp", "TCP Option - Timestamps", d.FtNone)
	hfTCPOptTSVal   = protoTCP.Field("tcp.options.timestamp.tsval", "Timestamp value", d.FtUint32)
	hfTCPOptTSEcr   = protoTCP.Field("tcp.options.timestamp.tsecr", "Timestamp echo reply", d.FtUint32)
	hfTCPOptTFO     = protoTCP.Field("tcp.options.tfo", "TCP Option - TCP Fast Open", d.FtNone)
	hfTCPOptTFOCk   = protoTCP.Field("tcp.options.tfo.cookie", "Fast Open Cookie", d.FtBytes)
	hfTCPOptTFOReq  = protoTCP.Field("tcp.options.tfo.request", "Fast Open Cookie Request", d.FtNone)
	hfTCPOptMPTCP   = protoTCP.Field("tcp.options.mptcp.subtype", "Multipath TCP subtype", d.FtUint8,
		d.WithMask(0xf0), d.WithVS(map[uint64]string{0: "Multipath Capable", 1: "Join Connection", 2: "Data Sequence Signal", 3: "Add Address", 4: "Remove Address", 5: "Change Subflow Priority", 6: "Fallback", 7: "Fast Close", 8: "Subflow Reset"}))
	hfTCPOptUnknown = protoTCP.Field("tcp.options.unknown.payload", "Payload", d.FtBytes)
	hfTCPTimeRel    = protoTCP.Field("tcp.time_relative", "Time since first frame in this TCP stream", d.FtRelTime)
	hfTCPTimeDelta  = protoTCP.Field("tcp.time_delta", "Time since previous frame in this TCP stream", d.FtRelTime)
	hfTCPPayload    = protoTCP.Field("tcp.payload", "TCP payload", d.FtBytes)
	eiTCPBadHdrLen  = protoTCP.Expert("tcp.bogus_header_length", d.GroupMalformed, d.SevError, "Bogus TCP header length")
	eiTCPConnSYN    = protoTCP.Expert("tcp.connection.syn", d.GroupSequence, d.SevChat, "Connection establish request (SYN)")
	eiTCPConnSYNACK = protoTCP.Expert("tcp.connection.sack", d.GroupSequence, d.SevChat, "Connection establish acknowledge (SYN+ACK)")
	eiTCPConnFIN    = protoTCP.Expert("tcp.connection.fin", d.GroupSequence, d.SevChat, "Connection finish (FIN)")
	eiTCPConnRST    = protoTCP.Expert("tcp.connection.rst", d.GroupSequence, d.SevWarn, "Connection reset (RST)")

	// TCPPortTable dispatches TCP payloads by port.
	TCPPortTable = d.Table("tcp.port")
	// TCPHeur holds heuristic dissectors for TCP payloads.
	TCPHeur = d.Heur("tcp")

	// TCPRelativeSeq shows relative sequence numbers (tcp.relative_sequence_numbers).
	TCPRelativeSeq = true
)

func init() {
	IPProtoTable.Add(6, d.NewHandle(protoTCP, dissectTCP))
}

type tcpFlow struct {
	base    uint32
	baseSet bool
	wsShift int8 // from SYN: >=0 shift, -2 SYN without WS option, -1 SYN not seen
	fin     bool
	rst     bool

	// Sequence analysis state (absolute sequence numbers).
	nextSeq         uint32
	nextSeqSet      bool
	nextSeqTS       int64
	nextSeqFrame    uint32
	maxSeqToBeAcked uint32
	maxSeqSet       bool
	lastAck         uint32
	lastAckSet      bool
	lastAckTS       int64
	window          uint32
	windowSet       bool
	lastFlags       uint16
	dupAckNum       uint32
	lastNonDupAck   uint32
	unacked         []unackedSeg
	pushBytes       uint32

	reasm tcpReasmFlow
}

type tcpConv struct {
	flows    [2]tcpFlow
	lastTS   int64
	complete uint8
	synTS    int64
	iRTT     int64
}

// tcpFrame is computed in the first pass and reused afterwards.
type tcpFrame struct {
	timeRel       int64
	timeDelta     int64
	ackRTT        int64
	rto           int64
	stream        uint32
	relSeq        uint32
	relAck        uint32
	dupAckNum     uint32
	dupAckFrame   uint32
	ackFrame      uint32
	rtoFrame      uint32
	bytesInFlight uint32
	hasBIF        bool
	pushBytes     uint32
	analysis      uint16
	winScale      int8
	dir           uint8
}

var protoTCPFrames = d.RegisterProto("TCP per-frame state", "_tcpstate", "_ws.tcpstate")

func tcpFrames(s *d.Session) *d.FrameTable[tcpFrame] {
	return d.SessionTable[tcpFrame](s, protoTCPFrames)
}

// TCPInfo describes the segment being dissected for payload dissectors.
type TCPInfo struct {
	Seq, NxtSeq, Ack uint32
	Flags            uint16
	Stream           uint32
	FromA            bool
}

// CurrentTCP is valid while a TCP payload dissector runs.
func CurrentTCP(pi *d.PacketInfo) *TCPInfo {
	v, _ := pi.Scratch(protoTCP).(*TCPInfo)
	return v
}

const tcpFlagNames = "FIN SYN RST PSH ACK URG ECE CWR AE"

func tcpFlagsText(flags uint16) string {
	var parts []string
	for i, n := range strings.Fields(tcpFlagNames) {
		if flags&(1<<uint(i)) != 0 {
			parts = append(parts, n)
		}
	}
	if flags&0xe00 != 0 {
		parts = append(parts, "Reserved")
	}
	if len(parts) == 0 {
		return "<None>"
	}
	return strings.Join(parts, ", ")
}

func tcpFlagsStr(flags uint16) string {
	const chars = "RRRACEUAPRSF"
	b := []rune(strings.Repeat("·", 12))
	for i := 0; i < 12; i++ {
		if flags&(1<<uint(11-i)) != 0 {
			b[i] = rune(chars[i])
		}
	}
	return string(b)
}

func dissectTCP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	sport, dport := uint32(tvb.U16(0)), uint32(tvb.U16(2))
	tt := tree.AddProtocol(protoTCP, tvb, 0, -1)
	addPort(tt, hfTCPSrcPort, tvb, 0, sport, "tcp")
	addPort(tt, hfTCPDstPort, tvb, 2, dport, "tcp")
	tt.AddHidden(hfTCPPort, tvb, 0, 2, d.Value{U: uint64(sport)})
	tt.AddHidden(hfTCPPort, tvb, 2, 2, d.Value{U: uint64(dport)})
	if pi.InErrorPkt {
		// Only the first 8 bytes of the segment are quoted in ICMP errors.
		_, seq := tt.AddUint(hfTCPSeqRaw, tvb, 4, 4)
		tt.SetText("Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %d", sport, dport, seq)
		return tvb.Len()
	}
	pi.SetProtocol("TCP")
	pi.PortType, pi.SrcPort, pi.DstPort = d.PortTCP, sport, dport

	seq, ack := tvb.U32(4), tvb.U32(8)
	b12 := tvb.U8(12)
	hlen := int(b12>>4) * 4
	flagsRaw := tvb.U16(12)
	flags := flagsRaw & 0x0fff
	win := uint32(tvb.U16(14))
	if hlen < 20 {
		tt.SetLen(20)
		n := tt.AddBits(hfTCPHdrLen, tvb, 12, 1, uint64(b12))
		n.AddExpert(eiTCPBadHdrLen, "Bogus TCP header length (%d, must be at least 20)", hlen)
		pi.SetInfof("%d → %d [BAD HEADER LEN %d]", sport, dport, hlen)
		return tvb.Len()
	}
	segLen := tvb.Reported() - hlen
	if segLen < 0 {
		segLen = 0
	}

	// Per-frame state from the first pass.
	sess := pi.Sess
	var fd *tcpFrame
	if pi.Visited {
		if v, ok := tcpFrames(sess).Get(pi.Num); ok {
			fd = &v
		}
	}
	if fd == nil {
		fd = tcpFirstPass(pi, tvb, seq, ack, flags, hlen, segLen)
		if !pi.Visited {
			tcpFrames(sess).Put(pi.Num, *fd)
		}
	}
	pi.Conv = sess.FindConversation(d.ConvTCP, pi.Src, pi.Dst, sport, dport)
	var st *tcpConv
	if pi.Conv != nil {
		st, _ = pi.Conv.Data(protoTCP).(*tcpConv)
	}

	relSeq, relAck := seq, ack
	if TCPRelativeSeq {
		relSeq, relAck = fd.relSeq, fd.relAck
	}
	nxt := relSeq + uint32(segLen)
	if flags&0x003 != 0 { // SYN or FIN occupies a sequence number
		nxt++
	}
	calcWin := win
	if flags&0x002 == 0 && fd.winScale >= 0 {
		calcWin = win << uint(fd.winScale)
	}

	tt.AddGenerated(hfTCPStream, d.Value{U: uint64(fd.stream)})
	addCompleteness(tt, st)
	tt.AddGenerated(hfTCPLen, d.Value{U: uint64(segLen)})
	if TCPRelativeSeq {
		sn := tt.AddUintValue(hfTCPSeq, tvb, 4, 4, uint64(relSeq))
		sn.AppendText("    (relative sequence number)")
	} else {
		tt.AddUintValue(hfTCPSeq, tvb, 4, 4, uint64(seq))
	}
	tt.AddUint(hfTCPSeqRaw, tvb, 4, 4)
	{
		tt.AddGenerated(hfTCPNxtSeq, d.Value{U: uint64(nxt)}).AppendText("    (relative sequence number)")
	}
	if flags&0x010 != 0 {
		an := tt.AddUintValue(hfTCPAck, tvb, 8, 4, uint64(relAck))
		if TCPRelativeSeq {
			an.AppendText("    (relative ack number)")
		}
		tt.AddUint(hfTCPAckRaw, tvb, 8, 4)
	} else {
		tt.AddUintValue(hfTCPAck, tvb, 8, 4, 0).SetText("Acknowledgment Number: 0")
		tt.AddUint(hfTCPAckRaw, tvb, 8, 4)
	}
	hn := tt.AddBits(hfTCPHdrLen, tvb, 12, 1, uint64(b12))
	hn.SetText("%s = Header Length: %d bytes (%d)", hfTCPHdrLen.BitPattern(uint64(b12)), hlen, b12>>4)
	fn := tt.AddBits(hfTCPFlags, tvb, 12, 2, uint64(flagsRaw))
	fn.SetText("Flags: 0x%03x (%s)", flags, tcpFlagsText(flags))
	for _, f := range []*d.FieldDef{hfTCPFlagRes, hfTCPFlagAE, hfTCPFlagCWR, hfTCPFlagECE, hfTCPFlagURG,
		hfTCPFlagACK, hfTCPFlagPSH, hfTCPFlagRST, hfTCPFlagSYN, hfTCPFlagFIN} {
		n := fn.AddBits(f, tvb, 12, 2, uint64(flags))
		switch {
		case f == hfTCPFlagSYN && flags&0x002 != 0:
			if flags&0x010 != 0 {
				n.AddExpert(eiTCPConnSYNACK, "")
			} else {
				n.AddExpert(eiTCPConnSYN, "")
			}
		case f == hfTCPFlagFIN && flags&0x001 != 0:
			n.AddExpert(eiTCPConnFIN, "")
		case f == hfTCPFlagRST && flags&0x004 != 0:
			n.AddExpert(eiTCPConnRST, "")
		}
	}
	fn.AddGenerated(hfTCPFlagStr, d.StringValue(tcpFlagsStr(flags)))
	tt.AddUint(hfTCPWinVal, tvb, 14, 2)
	tt.AddGenerated(hfTCPWin, d.Value{U: uint64(calcWin)})
	wsn := tt.AddGenerated(hfTCPWinScale, d.Value{U: uint64(int64(fd.winScale))})
	_ = wsn
	switch fd.winScale {
	case -1:
		wsn.SetText("[Window size scaling factor: -1 (unknown)]")
	case -2:
		wsn.SetText("[Window size scaling factor: -2 (no window scaling used)]")
	default:
		wsn.SetText("[Window size scaling factor: %d]", 1<<uint(fd.winScale))
	}
	ckn, _ := tt.AddUint(hfTCPChecksum, tvb, 16, 2)
	ckn.AppendText(" [unverified]")
	tt.AddGenerated(hfTCPCkStatus, d.Value{U: 2})
	tt.AddUint(hfTCPUrgent, tvb, 18, 2)

	var optInfo []string
	if hlen > 20 {
		optInfo = dissectTCPOptions(tt, tvb, 20, hlen, fd, flags)
	}

	addAnalysisTree(tt, fd, st, segLen)
	ts := tt.AddText(nil, 0, 0, "[Timestamps]")
	ts.AddGenerated(hfTCPTimeRel, d.RelTimeValue(fd.timeRel)).
		SetText("[Time since first frame in this TCP stream: %s seconds]", d.FormatRelTime(fd.timeRel))
	ts.AddGenerated(hfTCPTimeDelta, d.RelTimeValue(fd.timeDelta)).
		SetText("[Time since previous frame in this TCP stream: %s seconds]", d.FormatRelTime(fd.timeDelta))

	tt.SetLen(hlen)
	label := fmt.Sprintf("Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %d", sport, dport, relSeq)
	if flags&0x010 != 0 {
		label += fmt.Sprintf(", Ack: %d", relAck)
	}
	label += fmt.Sprintf(", Len: %d", segLen)
	tt.SetText("%s", label)

	if pi.WantColumns() {
		var b strings.Builder
		fmt.Fprintf(&b, "%s → %s [%s] Seq=%d", portLabel(sport, "tcp"), portLabel(dport, "tcp"), tcpFlagsText(flags), relSeq)
		if flags&0x010 != 0 {
			fmt.Fprintf(&b, " Ack=%d", relAck)
		}
		fmt.Fprintf(&b, " Win=%d Len=%d", calcWin, segLen)
		for _, o := range optInfo {
			b.WriteString(" " + o)
		}
		if pre := analysisPrefix(fd); pre != "" {
			// Analysis tags stay in front even when an application
			// dissector rewrites the Info column.
			pi.SetInfo(pre)
			pi.FenceInfo()
			pi.AppendInfo("%s", b.String())
		} else {
			pi.SetInfo(b.String())
		}
	}

	if segLen > 0 && tvb.Remaining(hlen) > 0 {
		payload := tvb.Sub(hlen, segLen)
		pn, _ := tt.AddBytes(hfTCPPayload, tvb, hlen, payload.Len())
		pn.SetText("TCP payload (%d byte%s)", segLen, plural(segLen))
		pi.SetScratch(protoTCP, &TCPInfo{Seq: relSeq, NxtSeq: nxt, Ack: relAck, Flags: flags, Stream: fd.stream, FromA: fd.dir == 0})
		tcpPayload(payload, pi, tree, tt, fd, st, seq, segLen)
	}
	return tvb.Len()
}

func tcpFirstPass(pi *d.PacketInfo, tvb *d.Tvb, seq, ack uint32, flags uint16, hlen, segLen int) *tcpFrame {
	sess := pi.Sess
	sport, dport := pi.SrcPort, pi.DstPort
	conv := sess.Conversation(pi, d.ConvTCP, pi.Src, pi.Dst, sport, dport)
	if conv == nil {
		return &tcpFrame{winScale: -1}
	}
	st, _ := conv.Data(protoTCP).(*tcpConv)
	syn := flags&0x002 != 0
	ackf := flags&0x010 != 0
	reused := false
	if st != nil && syn && !ackf {
		dir := 0
		if !conv.FromA(pi.Src, sport) {
			dir = 1
		}
		f := st.flows[dir]
		// Port reuse: a fresh SYN after the old connection ended.
		if (f.fin || f.rst || st.flows[1-dir].rst) && f.baseSet && f.base != seq {
			conv = sess.NewConversationAfter(pi, conv)
			st = nil
			reused = true
		}
	}
	if st == nil {
		st = &tcpConv{lastTS: pi.TS}
		st.flows[0].wsShift, st.flows[1].wsShift = -1, -1
		conv.SetData(protoTCP, st)
	}
	dir := 0
	if !conv.FromA(pi.Src, sport) {
		dir = 1
	}
	fl, rev := &st.flows[dir], &st.flows[1-dir]
	if syn {
		fl.base, fl.baseSet = seq, true
		fl.wsShift = -2
		// Peek at the window scale option.
		for off := 20; off+1 < hlen && tvb.Has(off, 1); {
			k := tvb.U8(off)
			if k == 0 {
				break
			}
			if k == 1 {
				off++
				continue
			}
			l := int(tvb.U8(off + 1))
			if l < 2 {
				break
			}
			if k == 3 && l == 3 && tvb.Has(off+2, 1) {
				fl.wsShift = int8(min(tvb.U8(off+2), 14))
			}
			off += l
		}
	} else if !fl.baseSet {
		fl.base, fl.baseSet = seq-1, true
	}
	if ackf && !rev.baseSet {
		rev.base, rev.baseSet = ack-1, true
	}
	if flags&0x001 != 0 {
		fl.fin = true
	}
	if flags&0x004 != 0 {
		fl.rst = true
	}
	fd := &tcpFrame{stream: conv.Index, dir: uint8(dir), relSeq: seq - fl.base, timeRel: pi.TS - conv.FirstTS, timeDelta: pi.TS - st.lastTS}
	if ackf {
		fd.relAck = ack - rev.base
	}
	// Scaling applies only when both SYNs carried the option.
	switch {
	case fl.wsShift >= 0 && rev.wsShift >= 0:
		fd.winScale = fl.wsShift
	case fl.wsShift == -2 || rev.wsShift == -2:
		fd.winScale = -2
	default:
		fd.winScale = -1
	}
	if TCPAnalyzeSeq {
		win := uint32(tvb.U16(14))
		if !syn && fd.winScale >= 0 {
			win <<= uint(fd.winScale)
		}
		st.analyze(fd, fl, rev, pi.Num, pi.TS, seq, ack, segLen, flags, win)
		if reused {
			fd.analysis |= taReusedPorts
		}
	}
	st.lastTS = pi.TS
	return fd
}

func dissectTCPOptions(tt *d.Node, tvb *d.Tvb, off, end int, fd *tcpFrame, flags uint16) []string {
	on, _ := tt.AddBytes(hfTCPOptions, tvb, off, end-off)
	n := end - off
	on.SetText("Options: (%d bytes)", n)
	var info []string
	var parts []string
	for off < end {
		kind := tvb.U8(off)
		switch kind {
		case 0:
			x, _ := on.AddBytes(hfTCPOptEOL, tvb, off, 1)
			x.SetText("TCP Option - End of Option List (EOL)")
			x.AddUint(hfTCPOptKind, tvb, off, 1)
			parts = append(parts, "End of Option List (EOL)")
			off = end
			continue
		case 1:
			x, _ := on.AddBytes(hfTCPOptNOP, tvb, off, 1)
			x.SetText("TCP Option - No-Operation (NOP)")
			x.AddUint(hfTCPOptKind, tvb, off, 1)
			parts = append(parts, "No-Operation (NOP)")
			off++
			continue
		}
		if off+1 >= end {
			break
		}
		l := int(tvb.U8(off + 1))
		if l < 2 || off+l > end {
			on.AddText(tvb, off, end-off, "TCP Option - %s: bad length %d", tcpOptKinds[uint64(kind)], l)
			break
		}
		var x *d.Node
		switch kind {
		case 2:
			x = on.AddValue(hfTCPOptMSS, tvb, off, l, d.Value{})
			x.AddUint(hfTCPOptKind, tvb, off, 1)
			x.AddUint(hfTCPOptLen, tvb, off+1, 1)
			if l == 4 {
				_, mss := x.AddUint(hfTCPOptMSSVal, tvb, off+2, 2)
				x.SetText("TCP Option - Maximum segment size: %d bytes", mss)
				info = append(info, fmt.Sprintf("MSS=%d", mss))
				parts = append(parts, "Maximum segment size")
			}
		case 3:
			x = on.AddValue(hfTCPOptWS, tvb, off, l, d.Value{})
			x.AddUint(hfTCPOptKind, tvb, off, 1)
			x.AddUint(hfTCPOptLen, tvb, off+1, 1)
			if l == 3 {
				_, sh := x.AddUint(hfTCPOptWSShift, tvb, off+2, 1)
				mult := uint64(1) << min(sh, 14)
				x.AddGenerated(hfTCPOptWSMult, d.Value{U: mult})
				x.SetText("TCP Option - Window scale: %d (multiply by %d)", sh, mult)
				info = append(info, fmt.Sprintf("WS=%d", mult))
				parts = append(parts, "Window scale")
			}
		case 4:
			x = on.AddValue(hfTCPOptSACKP, tvb, off, l, d.Value{})
			x.AddUint(hfTCPOptKind, tvb, off, 1)
			x.AddUint(hfTCPOptLen, tvb, off+1, 1)
			info = append(info, "SACK_PERM")
			parts = append(parts, "SACK permitted")
		case 5:
			x = on.AddValue(hfTCPOptSACK, tvb, off, l, d.Value{})
			x.AddUint(hfTCPOptKind, tvb, off, 1)
			x.AddUint(hfTCPOptLen, tvb, off+1, 1)
			cnt := 0
			var edges []string
			for p := off + 2; p+8 <= off+l; p += 8 {
				x.AddUint(hfTCPOptSACKLE, tvb, p, 4)
				x.AddUint(hfTCPOptSACKRE, tvb, p+4, 4)
				edges = append(edges, fmt.Sprintf("%d-%d", tvb.U32(p), tvb.U32(p+4)))
				cnt++
			}
			x.AddGenerated(hfTCPOptSACKCnt, d.Value{U: uint64(cnt)})
			x.SetText("TCP Option - SACK %s", strings.Join(edges, " "))
			for i, e := range edges {
				pp := strings.SplitN(e, "-", 2)
				info = append(info, fmt.Sprintf("SLE=%s SRE=%s", pp[0], pp[1]))
				_ = i
			}
			parts = append(parts, "SACK")
		case 8:
			x = on.AddValue(hfTCPOptTS, tvb, off, l, d.Value{})
			x.AddUint(hfTCPOptKind, tvb, off, 1)
			x.AddUint(hfTCPOptLen, tvb, off+1, 1)
			if l == 10 {
				_, tsv := x.AddUint(hfTCPOptTSVal, tvb, off+2, 4)
				_, tse := x.AddUint(hfTCPOptTSEcr, tvb, off+6, 4)
				x.SetText("TCP Option - Timestamps: TSval %d, TSecr %d", tsv, tse)
				info = append(info, fmt.Sprintf("TSval=%d TSecr=%d", tsv, tse))
				parts = append(parts, "Timestamps")
			}
		case 34:
			x = on.AddValue(hfTCPOptTFO, tvb, off, l, d.Value{})
			x.AddUint(hfTCPOptKind, tvb, off, 1)
			x.AddUint(hfTCPOptLen, tvb, off+1, 1)
			if l == 2 {
				x.AddValue(hfTCPOptTFOReq, tvb, off, 2, d.Value{})
				x.SetText("TCP Option - TFO Cookie Request")
				info = append(info, "TFO=R")
			} else {
				x.AddBytes(hfTCPOptTFOCk, tvb, off+2, l-2)
				info = append(info, "TFO=C")
			}
			parts = append(parts, "TFO")
		case 30:
			x = on.AddText(tvb, off, l, "TCP Option - Multipath TCP")
			x.AddUint(hfTCPOptKind, tvb, off, 1)
			x.AddUint(hfTCPOptLen, tvb, off+1, 1)
			if l > 2 {
				x.AddUint(hfTCPOptMPTCP, tvb, off+2, 1)
			}
			parts = append(parts, "Multipath TCP")
		default:
			name := tcpOptKinds[uint64(kind)]
			if name == "" {
				name = fmt.Sprintf("Unknown (0x%02x)", kind)
			}
			x = on.AddText(tvb, off, l, "TCP Option - %s", name)
			x.AddUint(hfTCPOptKind, tvb, off, 1)
			x.AddUint(hfTCPOptLen, tvb, off+1, 1)
			if l > 2 {
				x.AddBytes(hfTCPOptUnknown, tvb, off+2, l-2)
			}
			parts = append(parts, name)
		}
		off += l
	}
	on.SetText("Options: (%d bytes), %s", n, strings.Join(parts, ", "))
	_ = fd
	_ = flags
	return info
}

// dispatchPorts tries the port table (lower port first), heuristics, then data.
func dispatchPorts(table *d.UintTable, heur *d.HeurList, payload *d.Tvb, pi *d.PacketInfo, tree *d.Node, sport, dport uint32) {
	low, high := sport, dport
	if low > high {
		low, high = high, low
	}
	if table == UDPPortTable {
		if _, rtcp, ok := rtpFor(pi, payload); ok {
			h := rtpHandle
			if rtcp {
				h = rtcpHandle
			}
			if pi.Call(h, payload, tree) > 0 {
				return
			}
		}
	}
	if table == TCPPortTable {
		if e, ok := ftpDataFor(pi); ok {
			_ = e
			if h := d.FindHandle("ftp-data"); h != nil && pi.Call(h, payload, tree) > 0 {
				return
			}
		}
	}
	if low != 0 {
		if _, ok := table.Try(uint64(low), payload, pi, tree); ok {
			return
		}
	}
	if high != low {
		if _, ok := table.Try(uint64(high), payload, pi, tree); ok {
			return
		}
	}
	if heur != nil && heur.Try(payload, pi, tree) {
		return
	}
	pi.Call(DataHandle, payload, tree)
}
