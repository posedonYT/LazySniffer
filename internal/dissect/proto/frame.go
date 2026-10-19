// Package proto holds the native protocol dissectors.
package proto

import (
	"fmt"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/pcapio"
)

var (
	protoFrame = d.RegisterProto("Frame", "Frame", "frame")

	hfFrameIfaceID   = protoFrame.Field("frame.interface_id", "Interface id", d.FtUint32)
	hfFrameIfaceName = protoFrame.Field("frame.interface_name", "Interface name", d.FtString)
	hfFrameIfaceDesc = protoFrame.Field("frame.interface_description", "Interface description", d.FtString)
	hfFrameEncap     = protoFrame.Field("frame.encap_type", "Encapsulation type", d.FtUint16)
	hfFrameTime      = protoFrame.Field("frame.time", "Arrival Time", d.FtAbsTime)
	hfFrameTimeUTC   = protoFrame.Field("frame.time_utc", "UTC Arrival Time", d.FtAbsTime)
	hfFrameTimeEpoch = protoFrame.Field("frame.time_epoch", "Epoch Arrival Time", d.FtAbsTime)
	hfFrameTimeDelta = protoFrame.Field("frame.time_delta", "Time delta from previous captured frame", d.FtRelTime)
	hfFrameTimeRel   = protoFrame.Field("frame.time_relative", "Time since reference or first frame", d.FtRelTime)
	hfFrameNumber    = protoFrame.Field("frame.number", "Frame Number", d.FtUint32)
	hfFrameLen       = protoFrame.Field("frame.len", "Frame Length", d.FtUint32)
	hfFrameCapLen    = protoFrame.Field("frame.cap_len", "Capture Length", d.FtUint32)
	hfFrameMarked    = protoFrame.Field("frame.marked", "Frame is marked", d.FtBool)
	hfFrameIgnored   = protoFrame.Field("frame.ignored", "Frame is ignored", d.FtBool)
	hfFrameProtocols = protoFrame.Field("frame.protocols", "Protocols in frame", d.FtString)
	hfFrameComment   = protoFrame.Field("frame.comment", "Comment", d.FtString)
	hfFrameFlags     = protoFrame.Field("frame.packet_flags", "Packet flags", d.FtUint32, d.WithBase(d.BaseHex))
	hfFrameFlagsDir  = protoFrame.Field("frame.packet_flags_direction", "Direction", d.FtUint32,
		d.WithMask(0x3), d.WithParentBits(32), d.WithBase(d.BaseHex),
		d.WithVS(map[uint64]string{0: "Information not available", 1: "Inbound", 2: "Outbound"}))
	eiFrameComment = protoFrame.Expert("frame.comment.expert", d.GroupComments, d.SevComment, "Formatted comment")

	hfDataData = protoData.Field("data.data", "Data", d.FtBytes)
	hfDataLen  = protoData.Field("data.len", "Length", d.FtUint32)
	protoData  = d.RegisterProto("Data", "Data", "data")

	// DataHandle dissects undecoded bytes.
	DataHandle = d.RegisterHandle("data", d.NewHandle(protoData, dissectData))
	// EncapTable dispatches on the capture link type.
	EncapTable = d.Table("wtap_encap")
)

func init() {
	d.SetFrameHandle(d.NewHandle(protoFrame, dissectFrame))
}

func dissectFrame(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	sess := pi.Sess
	var iface pcapio.Interface
	if int(pi.Iface) < len(sess.Interfaces) {
		iface = sess.Interfaces[pi.Iface]
	}
	ifName := iface.Name
	ft := tree.AddProtocol(protoFrame, tvb, 0, -1)
	if tree.Tree().Full() {
		lbl := &strings.Builder{}
		lbl.WriteString("Frame ")
		lbl.WriteString(d.PortString(pi.Num))
		fmt.Fprintf(lbl, ": %d bytes on wire (%d bits), %d bytes captured (%d bits)", pi.Len, pi.Len*8, pi.CapLen, pi.CapLen*8)
		if ifName != "" {
			lbl.WriteString(" on interface " + ifName)
		}
		lbl.WriteString(", id " + d.PortString(pi.Iface))
		ft.SetText("%s", lbl.String())
	}

	if len(pi.Comments) > 0 {
		ct := ft.AddText(nil, 0, 0, "Packet comments")
		for _, c := range pi.Comments {
			n := ct.AddValue(hfFrameComment, nil, 0, 0, d.StringValue(c))
			n.AddExpert(eiFrameComment, "%s", c)
		}
	}

	in := ft.AddUintValue(hfFrameIfaceID, nil, 0, 0, uint64(pi.Iface))
	if ifName != "" {
		in.AppendText(" (%s)", ifName)
		in.AddValue(hfFrameIfaceName, nil, 0, 0, d.StringValue(ifName))
	}
	if iface.Description != "" {
		in.AddValue(hfFrameIfaceDesc, nil, 0, 0, d.StringValue(iface.Description))
	}
	if pi.EPBFlags != 0 {
		fl := ft.AddUintValue(hfFrameFlags, nil, 0, 0, uint64(pi.EPBFlags))
		fl.AddBits(hfFrameFlagsDir, nil, 0, 0, uint64(pi.EPBFlags))
	}
	enc := ft.AddUintValue(hfFrameEncap, nil, 0, 0, uint64(pi.LinkType))
	enc.SetText("Encapsulation type: %s (%d)", pi.LinkType, pi.LinkType)
	ft.AddValue(hfFrameTime, nil, 0, 0, d.TimeValue(pi.TS))
	ft.AddValue(hfFrameTimeUTC, nil, 0, 0, d.TimeValue(pi.TS)).
		SetText("UTC Arrival Time: %s", d.FormatAbsTime(pi.TS, true))
	ft.AddValue(hfFrameTimeEpoch, nil, 0, 0, d.TimeValue(pi.TS)).
		SetText("Epoch Arrival Time: %s", d.FormatRelTime(pi.TS))
	ft.AddValue(hfFrameTimeDelta, nil, 0, 0, d.RelTimeValue(pi.DeltaTS)).SetGenerated()
	ft.AddValue(hfFrameTimeRel, nil, 0, 0, d.RelTimeValue(pi.RelTS)).SetGenerated()
	ft.AddUintValue(hfFrameNumber, nil, 0, 0, uint64(pi.Num))
	ft.AddUintValue(hfFrameLen, nil, 0, 0, uint64(pi.Len)).SetText("Frame Length: %s", bytesBits(int(pi.Len)))
	ft.AddUintValue(hfFrameCapLen, nil, 0, 0, uint64(pi.CapLen)).SetText("Capture Length: %s", bytesBits(int(pi.CapLen)))
	ft.AddValue(hfFrameMarked, nil, 0, 0, d.BoolValue(pi.Marked)).SetGenerated()
	ft.AddValue(hfFrameIgnored, nil, 0, 0, d.BoolValue(pi.Ignored)).SetGenerated()

	// frame.protocols is only known after the payload has been dissected.
	t := tree.Tree()
	protosIdx := len(t.Vals)
	protosNode := ft.AddValue(hfFrameProtocols, nil, 0, 0, d.StringValue("")).SetGenerated()
	recorded := len(t.Vals) > protosIdx

	if pi.Ignored {
		pi.SetProtocol("")
		pi.SetInfo("<Ignored>")
	} else if _, ok := EncapTable.Try(uint64(pi.LinkType), tvb, pi, tree); !ok {
		pi.SetProtocol("UNKNOWN")
		pi.SetInfo("WTAP_ENCAP = " + d.PortString(uint32(pi.LinkType)))
		pi.Call(DataHandle, tvb, tree)
	}

	protos := strings.Join(pi.Protocols, ":")
	if !protosNode.IsSink() {
		protosNode.Value = d.StringValue(protos)
	}
	if recorded {
		t.Vals[protosIdx].V = d.StringValue(protos)
	}
	return tvb.Len()
}

func bytesBits(n int) string {
	var b strings.Builder
	writeBytesBits(&b, n)
	return b.String()
}

func writeBytesBits(b *strings.Builder, n int) {
	b.WriteString(d.PortString(uint32(n)))
	b.WriteString(" bytes (")
	b.WriteString(d.PortString(uint32(n * 8)))
	b.WriteString(" bits)")
}

func dissectData(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	n := tvb.Len()
	if n == 0 {
		return 0
	}
	dt := tree.AddProtocol(protoData, tvb, 0, n)
	dt.SetText("Data (%d byte%s)", n, plural(n))
	dt.AddBytes(hfDataData, tvb, 0, n)
	dt.AddGenerated(hfDataLen, d.Value{U: uint64(n)})
	return n
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
