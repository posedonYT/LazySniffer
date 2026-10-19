package proto

import (
	"fmt"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

// TCP analysis flags (Wireshark's TCP_A_*).
const (
	taRetrans uint16 = 1 << iota
	taFastRetrans
	taSpurious
	taOutOfOrder
	taLost
	taAckLost
	taWinUpdate
	taWinFull
	taKeepAlive
	taKeepAliveAck
	taDupAck
	taZeroWin
	taZeroWinProbe
	taZeroWinProbeAck
	taReusedPorts
)

// Conversation completeness bits (tcp.completeness).
const (
	tcSYN    uint8 = 1
	tcSYNACK uint8 = 2
	tcACK    uint8 = 4
	tcDATA   uint8 = 8
	tcFIN    uint8 = 16
	tcRST    uint8 = 32
)

var (
	hfTCPAnalysis       = protoTCP.Field("tcp.analysis", "SEQ/ACK analysis", d.FtNone)
	hfTCPAnalysisFlags  = protoTCP.Field("tcp.analysis.flags", "TCP Analysis Flags", d.FtNone)
	hfTCPAcksFrame      = protoTCP.Field("tcp.analysis.acks_frame", "This is an ACK to the segment in frame", d.FtFrameNum)
	hfTCPAckRTT         = protoTCP.Field("tcp.analysis.ack_rtt", "The RTT to ACK the segment was", d.FtRelTime)
	hfTCPInitialRTT     = protoTCP.Field("tcp.analysis.initial_rtt", "iRTT", d.FtRelTime)
	hfTCPBytesInFlight  = protoTCP.Field("tcp.analysis.bytes_in_flight", "Bytes in flight", d.FtUint32)
	hfTCPPushBytes      = protoTCP.Field("tcp.analysis.push_bytes_sent", "Bytes sent since last PSH flag", d.FtUint32)
	hfTCPDupAckNum      = protoTCP.Field("tcp.analysis.duplicate_ack_num", "Duplicate ACK #", d.FtUint32)
	hfTCPDupAckFrame    = protoTCP.Field("tcp.analysis.duplicate_ack_frame", "Duplicate to the ACK in frame", d.FtFrameNum)
	hfTCPRTO            = protoTCP.Field("tcp.analysis.rto", "The RTO for this segment was", d.FtRelTime)
	hfTCPRTOFrame       = protoTCP.Field("tcp.analysis.rto_frame", "RTO based on delta from frame", d.FtFrameNum)
	hfTCPCompleteness   = protoTCP.Field("tcp.completeness", "Conversation completeness", d.FtUint8)
	hfTCPComplRST       = protoTCP.Field("tcp.completeness.rst", "RST", d.FtBool, d.WithMask(0x20), d.WithTFS(d.TFSPresent))
	hfTCPComplFIN       = protoTCP.Field("tcp.completeness.fin", "FIN", d.FtBool, d.WithMask(0x10), d.WithTFS(d.TFSPresent))
	hfTCPComplData      = protoTCP.Field("tcp.completeness.data", "Data", d.FtBool, d.WithMask(0x08), d.WithTFS(d.TFSPresent))
	hfTCPComplACK       = protoTCP.Field("tcp.completeness.ack", "ACK", d.FtBool, d.WithMask(0x04), d.WithTFS(d.TFSPresent))
	hfTCPComplSYNACK    = protoTCP.Field("tcp.completeness.syn-ack", "SYN-ACK", d.FtBool, d.WithMask(0x02), d.WithTFS(d.TFSPresent))
	hfTCPComplSYN       = protoTCP.Field("tcp.completeness.syn", "SYN", d.FtBool, d.WithMask(0x01), d.WithTFS(d.TFSPresent))
	hfTCPComplStr       = protoTCP.Field("tcp.completeness.str", "Completeness Flags", d.FtString)
	eiTCPRetrans        = protoTCP.Expert("tcp.analysis.retransmission", d.GroupSequence, d.SevNote, "This frame is a (suspected) retransmission")
	eiTCPFastRetrans    = protoTCP.Expert("tcp.analysis.fast_retransmission", d.GroupSequence, d.SevNote, "This frame is a (suspected) fast retransmission")
	eiTCPSpurious       = protoTCP.Expert("tcp.analysis.spurious_retransmission", d.GroupSequence, d.SevNote, "This frame is a (suspected) spurious retransmission")
	eiTCPOutOfOrder     = protoTCP.Expert("tcp.analysis.out_of_order", d.GroupSequence, d.SevWarn, "This frame is a (suspected) out-of-order segment")
	eiTCPReusedPorts    = protoTCP.Expert("tcp.analysis.reused_ports", d.GroupSequence, d.SevNote, "A new tcp session is started with the same ports as an earlier session in this trace")
	eiTCPLost           = protoTCP.Expert("tcp.analysis.lost_segment", d.GroupSequence, d.SevWarn, "Previous segment(s) not captured (common at capture start)")
	eiTCPAckLost        = protoTCP.Expert("tcp.analysis.ack_lost_segment", d.GroupSequence, d.SevWarn, "ACKed segment that wasn't captured (common at capture start)")
	eiTCPWinUpdate      = protoTCP.Expert("tcp.analysis.window_update", d.GroupSequence, d.SevChat, "TCP window update")
	eiTCPWinFull        = protoTCP.Expert("tcp.analysis.window_full", d.GroupSequence, d.SevWarn, "TCP window specified by the receiver is now completely full")
	eiTCPKeepAlive      = protoTCP.Expert("tcp.analysis.keep_alive", d.GroupSequence, d.SevNote, "TCP keep-alive segment")
	eiTCPKeepAliveAck   = protoTCP.Expert("tcp.analysis.keep_alive_ack", d.GroupSequence, d.SevNote, "ACK to a TCP keep-alive segment")
	eiTCPDupAck         = protoTCP.Expert("tcp.analysis.duplicate_ack", d.GroupSequence, d.SevNote, "Duplicate ACK")
	eiTCPZeroWin        = protoTCP.Expert("tcp.analysis.zero_window", d.GroupSequence, d.SevWarn, "TCP Zero Window segment")
	eiTCPZeroWinProbe   = protoTCP.Expert("tcp.analysis.zero_window_probe", d.GroupSequence, d.SevNote, "TCP Zero Window Probe")
	eiTCPZeroWinProbeAk = protoTCP.Expert("tcp.analysis.zero_window_probe_ack", d.GroupSequence, d.SevNote, "ACK to a TCP Zero Window Probe")

	// TCPAnalyzeSeq enables sequence analysis (tcp.analyze_sequence_numbers).
	TCPAnalyzeSeq = true
)

// analysisInfo maps flags to their Info column tags, in display order.
var analysisInfo = []struct {
	flag uint16
	tag  string
	ei   **d.ExpertField
}{
	{taReusedPorts, "TCP Port numbers reused", &eiTCPReusedPorts},
	{taLost, "TCP Previous segment not captured", &eiTCPLost},
	{taAckLost, "TCP ACKed unseen segment", &eiTCPAckLost},
	{taSpurious, "TCP Spurious Retransmission", &eiTCPSpurious},
	{taFastRetrans, "TCP Fast Retransmission", &eiTCPFastRetrans},
	{taRetrans, "TCP Retransmission", &eiTCPRetrans},
	{taOutOfOrder, "TCP Out-Of-Order", &eiTCPOutOfOrder},
	{taWinUpdate, "TCP Window Update", &eiTCPWinUpdate},
	{taWinFull, "TCP Window Full", &eiTCPWinFull},
	{taKeepAlive, "TCP Keep-Alive", &eiTCPKeepAlive},
	{taKeepAliveAck, "TCP Keep-Alive ACK", &eiTCPKeepAliveAck},
	{taDupAck, "TCP Dup ACK", &eiTCPDupAck},
	{taZeroWin, "TCP ZeroWindow", &eiTCPZeroWin},
	{taZeroWinProbe, "TCP ZeroWindowProbe", &eiTCPZeroWinProbe},
	{taZeroWinProbeAck, "TCP ZeroWindowProbeAck", &eiTCPZeroWinProbeAk},
}

type unackedSeg struct {
	frame    uint32
	seq, nxt uint32
	ts       int64
}

func seqLT(a, b uint32) bool { return int32(a-b) < 0 }
func seqLE(a, b uint32) bool { return int32(a-b) <= 0 }
func seqGT(a, b uint32) bool { return int32(a-b) > 0 }

// analyze runs Wireshark's sequence analysis for one segment in the first
// pass. fl is the sending direction, rev the other one. window is scaled.
func (st *tcpConv) analyze(fd *tcpFrame, fl, rev *tcpFlow, num uint32, ts int64, seq, ack uint32, segLen int, flags uint16, window uint32) {
	syn, fin, rst, ackf, psh := flags&0x002 != 0, flags&0x001 != 0, flags&0x004 != 0, flags&0x010 != 0, flags&0x008 != 0
	special := syn || fin || rst
	var a uint16
	sl := uint32(segLen)

	switch {
	// Zero window probe: one byte at the next sequence number while the peer's window is zero.
	case segLen == 1 && fl.nextSeqSet && seq == fl.nextSeq && rev.windowSet && rev.window == 0:
		a |= taZeroWinProbe
		goto finishedFwd
	}
	if window == 0 && !special {
		a |= taZeroWin
	}
	if fl.nextSeqSet && seqGT(seq, fl.nextSeq) && !rst {
		a |= taLost
	}
	if segLen <= 1 && !special && fl.nextSeqSet && seq == fl.nextSeq-1 {
		a |= taKeepAlive
	}
	if segLen == 0 && window != 0 && fl.windowSet && window != fl.window && fl.nextSeqSet && seq == fl.nextSeq &&
		fl.lastAckSet && ack == fl.lastAck && !special {
		a |= taWinUpdate
	}
	if segLen > 0 && rev.windowSet && rev.lastAckSet && seq+sl == rev.lastAck+rev.window && !special {
		a |= taWinFull
	}
	if segLen == 0 && fl.windowSet && window == fl.window && fl.nextSeqSet && seq == fl.nextSeq &&
		fl.lastAckSet && ack == fl.lastAck && rev.lastFlags&taKeepAlive != 0 && !special {
		a |= taKeepAliveAck
		goto finishedFwd
	}
	if segLen == 0 && window == 0 && fl.windowSet && window == fl.window && fl.nextSeqSet && seq == fl.nextSeq &&
		fl.lastAckSet && (ack == fl.lastAck || ack == fl.lastAck+1) && rev.lastFlags&taZeroWinProbe != 0 && !special {
		a |= taZeroWinProbeAck
		goto finishedFwd
	}
	if segLen == 0 && fl.windowSet && window == fl.window && fl.nextSeqSet && seq == fl.nextSeq &&
		fl.lastAckSet && ack == fl.lastAck && ackf && !special {
		fl.dupAckNum++
		a |= taDupAck
		fd.dupAckNum = fl.dupAckNum
		fd.dupAckFrame = fl.lastNonDupAck
	}

finishedFwd:
	if a&taDupAck == 0 {
		fl.lastNonDupAck = num
		fl.dupAckNum = 0
	}
	// ACKs for data we never saw.
	if ackf && rev.maxSeqSet && seqGT(ack, rev.maxSeqToBeAcked) {
		a |= taAckLost
		rev.maxSeqToBeAcked = ack
	}

	// Retransmission, fast retransmission, spurious retransmission or out-of-order.
	if (segLen > 0 || syn || fin) && fl.nextSeqSet && seqLT(seq, fl.nextSeq) && a&(taKeepAlive|taZeroWinProbe) == 0 {
		t := ts - fl.nextSeqTS
		switch {
		case segLen > 0 && rev.lastAckSet && seqLE(seq+sl, rev.lastAck):
			a |= taSpurious
		case ts-rev.lastAckTS < 20e6 && rev.dupAckNum >= 2 && rev.lastAckSet && rev.lastAck == seq:
			a |= taFastRetrans
		default:
			ooo := int64(3e6)
			if st.iRTT > 0 {
				ooo = st.iRTT
			}
			if t < ooo && fl.nextSeq != seq+sl {
				a |= taOutOfOrder
			} else {
				a |= taRetrans
			}
		}
		if a&(taRetrans|taFastRetrans) != 0 {
			for _, u := range fl.unacked {
				if u.seq == seq {
					fd.rtoFrame = u.frame
					fd.rto = ts - u.ts
					break
				}
			}
		}
	}

	next := seq + sl
	if syn || fin {
		next++
	}
	if (segLen > 0 || syn || fin) && a&(taRetrans|taFastRetrans|taSpurious|taOutOfOrder|taZeroWinProbe) == 0 {
		if !fl.nextSeqSet || seqGT(next, fl.nextSeq) {
			fl.nextSeq, fl.nextSeqSet, fl.nextSeqTS, fl.nextSeqFrame = next, true, ts, num
		}
		if !fl.maxSeqSet || seqGT(next, fl.maxSeqToBeAcked) {
			fl.maxSeqToBeAcked, fl.maxSeqSet = next, true
		}
		if len(fl.unacked) >= 512 {
			// Never acknowledged (e.g. one-sided capture): keep the newest.
			n := copy(fl.unacked, fl.unacked[256:])
			fl.unacked = fl.unacked[:n]
		}
		fl.unacked = append(fl.unacked, unackedSeg{frame: num, seq: seq, nxt: next, ts: ts})
	} else if !fl.nextSeqSet {
		// Pure ACKs establish where the next segment should start.
		fl.nextSeq, fl.nextSeqSet, fl.nextSeqTS, fl.nextSeqFrame = next, true, ts, num
	}

	// Which of the peer's segments does this ACK cover?
	if ackf {
		keep := rev.unacked[:0]
		var last *unackedSeg
		for i := range rev.unacked {
			u := rev.unacked[i]
			if seqLE(u.nxt, ack) {
				uu := u
				last = &uu
				continue
			}
			keep = append(keep, u)
		}
		rev.unacked = keep
		if last != nil && a&taDupAck == 0 {
			fd.ackFrame = last.frame
			fd.ackRTT = ts - last.ts
		}
		fl.lastAck, fl.lastAckSet, fl.lastAckTS = ack, true, ts
	}
	fl.window, fl.windowSet = window, true

	if segLen > 0 {
		fl.pushBytes += sl
		fd.pushBytes = fl.pushBytes
		if psh {
			fl.pushBytes = 0
		}
		// Bytes in flight: data sent but not yet acknowledged by the peer.
		// Wireshark leaves it out until the peer's ACK number is known and
		// does not count a FIN carried by the segment.
		if rev.lastAckSet {
			fd.hasBIF = true
			if fl.nextSeqSet {
				fd.bytesInFlight = fl.nextSeq - rev.lastAck
				if fin {
					fd.bytesInFlight--
				}
			} else {
				fd.bytesInFlight = sl
			}
		}
	}

	// Handshake timing and completeness.
	switch {
	case syn && !ackf:
		st.complete |= tcSYN
		st.synTS = ts
	case syn && ackf:
		st.complete |= tcSYNACK
	case ackf && st.complete&tcSYNACK != 0 && st.complete&tcACK == 0:
		st.complete |= tcACK
		if st.iRTT == 0 && st.synTS != 0 {
			st.iRTT = ts - st.synTS
		}
	}
	if segLen > 0 {
		st.complete |= tcDATA
	}
	if fin {
		st.complete |= tcFIN
	}
	if rst {
		st.complete |= tcRST
	}
	fl.lastFlags = a
	fd.analysis = a
}

// analysisPrefix renders the Info column tags of a frame.
func analysisPrefix(fd *tcpFrame) string {
	if fd.analysis == 0 {
		return ""
	}
	var b strings.Builder
	for _, ai := range analysisInfo {
		if fd.analysis&ai.flag == 0 {
			continue
		}
		tag := ai.tag
		if ai.flag == taDupAck {
			tag = fmt.Sprintf("TCP Dup ACK %d#%d", fd.dupAckFrame, fd.dupAckNum)
		}
		b.WriteString("[" + tag + "] ")
	}
	return b.String()
}

func completenessText(c uint8) string {
	switch {
	case c&(tcSYN|tcSYNACK|tcACK) == tcSYN|tcSYNACK|tcACK && c&(tcFIN|tcRST) != 0:
		if c&tcDATA != 0 {
			return "Complete, WITH_DATA"
		}
		return "Complete, NO_DATA"
	}
	var parts []string
	for _, x := range []struct {
		b uint8
		s string
	}{{tcSYN, "SYN"}, {tcSYNACK, "SYN_ACK"}, {tcACK, "ACK"}, {tcDATA, "DATA"}, {tcFIN, "FIN"}, {tcRST, "RST"}} {
		if c&x.b != 0 {
			parts = append(parts, x.s)
		}
	}
	if len(parts) == 0 {
		return "Incomplete"
	}
	return "Incomplete, " + strings.Join(parts, "_")
}

func completenessStr(c uint8) string {
	chars := []string{"R", "F", "D", "A", "S", "S"}
	bits := []uint8{tcRST, tcFIN, tcDATA, tcACK, tcSYNACK, tcSYN}
	var b strings.Builder
	for i, bit := range bits {
		if c&bit != 0 {
			b.WriteString(chars[i])
		} else {
			b.WriteString("·")
		}
	}
	return b.String()
}

// addAnalysisTree shows the [SEQ/ACK analysis] subtree and expert items.
func addAnalysisTree(tt *d.Node, fd *tcpFrame, st *tcpConv, segLen int) {
	show := fd.analysis != 0 || fd.ackFrame != 0 || (st != nil && st.iRTT > 0) || segLen > 0
	if !show {
		return
	}
	an := tt.AddValue(hfTCPAnalysis, nil, 0, 0, d.Value{}).SetGenerated()
	an.SetText("[SEQ/ACK analysis]")
	if fd.ackFrame != 0 {
		an.AddGenerated(hfTCPAcksFrame, d.Value{U: uint64(fd.ackFrame)}).SetLink(fd.ackFrame)
		an.AddGenerated(hfTCPAckRTT, d.RelTimeValue(fd.ackRTT)).
			SetText("[The RTT to ACK the segment was: %s seconds]", d.FormatRelTime(fd.ackRTT))
	}
	if st != nil && st.iRTT > 0 {
		an.AddGenerated(hfTCPInitialRTT, d.RelTimeValue(st.iRTT)).
			SetText("[iRTT: %s seconds]", d.FormatRelTime(st.iRTT))
	}
	if segLen > 0 {
		if fd.hasBIF {
			an.AddGenerated(hfTCPBytesInFlight, d.Value{U: uint64(fd.bytesInFlight)})
		}
		an.AddGenerated(hfTCPPushBytes, d.Value{U: uint64(fd.pushBytes)})
	}
	if fd.analysis == 0 {
		return
	}
	af := an.AddValue(hfTCPAnalysisFlags, nil, 0, 0, d.Value{}).SetGenerated()
	af.SetText("[TCP Analysis Flags]")
	for _, ai := range analysisInfo {
		if fd.analysis&ai.flag == 0 {
			continue
		}
		e := *ai.ei
		if ai.flag == taDupAck {
			af.AddExpert(e, "Duplicate ACK (#%d)", fd.dupAckNum)
			continue
		}
		af.AddExpert(e, "")
	}
	if fd.analysis&taDupAck != 0 {
		an.AddGenerated(hfTCPDupAckNum, d.Value{U: uint64(fd.dupAckNum)})
		an.AddGenerated(hfTCPDupAckFrame, d.Value{U: uint64(fd.dupAckFrame)}).SetLink(fd.dupAckFrame)
	}
	if fd.rtoFrame != 0 {
		an.AddGenerated(hfTCPRTO, d.RelTimeValue(fd.rto)).
			SetText("[The RTO for this segment was: %s seconds]", d.FormatRelTime(fd.rto))
		an.AddGenerated(hfTCPRTOFrame, d.Value{U: uint64(fd.rtoFrame)}).SetLink(fd.rtoFrame)
	}
}

func addCompleteness(tt *d.Node, st *tcpConv) {
	if st == nil {
		return
	}
	c := st.complete
	cn := tt.AddGenerated(hfTCPCompleteness, d.Value{U: uint64(c)})
	cn.SetText("[Conversation completeness: %s (%d)]", completenessText(c), c)
	for _, f := range []*d.FieldDef{hfTCPComplRST, hfTCPComplFIN, hfTCPComplData, hfTCPComplACK, hfTCPComplSYNACK, hfTCPComplSYN} {
		cn.AddBits(f, nil, 0, 0, uint64(c)).SetGenerated()
	}
	cn.AddGenerated(hfTCPComplStr, d.StringValue(completenessStr(c)))
}
