package proto

import (
	"fmt"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	protoGRPC    = d.RegisterProto("GRPC Message", "GRPC", "grpc")
	hfGRPCComp   = protoGRPC.Field("grpc.compressed_flag", "Compressed Flag", d.FtUint8)
	hfGRPCLen    = protoGRPC.Field("grpc.message_length", "Message Length", d.FtUint32)
	hfGRPCMsg    = protoGRPC.Field("grpc.message_data", "Message Data", d.FtBytes)
	protoPB      = d.RegisterProto("Protocol Buffers", "ProtoBuf", "protobuf")
	hfPBField    = protoPB.Field("protobuf.field", "Field", d.FtNone)
	hfPBNumber   = protoPB.Field("protobuf.field.number", "Field Number", d.FtUint32)
	hfPBWire     = protoPB.Field("protobuf.field.wire_type", "Wire Type", d.FtUint8)
	hfPBVarint   = protoPB.Field("protobuf.field.value.varint", "Varint", d.FtUint64)
	hfPBFixed    = protoPB.Field("protobuf.field.value.fixed", "Fixed", d.FtUint64)
	hfPBString   = protoPB.Field("protobuf.field.value.string", "String", d.FtString)
	hfPBBytes    = protoPB.Field("protobuf.field.value.bytes", "Bytes", d.FtBytes)
	grpcHandle   = d.RegisterHandle("grpc", d.NewHandle(protoGRPC, dissectGRPC))
	pbHandle     = d.RegisterHandle("protobuf", d.NewHandle(protoPB, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int { return dissectProtobuf(tvb, tree, 0) }))
	dohHandle    = d.RegisterHandle("dns-doh", d.NewHandle(protoDNS, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int { return DissectDNSMessage(tvb, pi, tree) }))
	grpcWireName = map[protowire.Type]string{protowire.VarintType: "Varint", protowire.Fixed32Type: "32-bit", protowire.Fixed64Type: "64-bit",
		protowire.BytesType: "Length-delimited", protowire.StartGroupType: "Start group", protowire.EndGroupType: "End group"}
)

func init() {
	for _, ct := range []string{"application/grpc", "application/grpc+proto", "application/grpc-web", "application/grpc-web+proto"} {
		MediaTypes[ct] = grpcHandle
	}
	MediaTypes["application/x-protobuf"] = pbHandle
	MediaTypes["application/protobuf"] = pbHandle
	MediaTypes["application/vnd.google.protobuf"] = pbHandle
	MediaTypes["application/dns-message"] = dohHandle
}

// dissectGRPC walks length-prefixed gRPC messages and decodes each one as
// schema-less protobuf.
func dissectGRPC(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	gt := tree.AddProtocol(protoGRPC, tvb, 0, -1)
	pi.SetProtocol("GRPC")
	for off := 0; tvb.Remaining(off) >= 5; {
		l := int(tvb.U32(off + 1))
		mt := gt.AddText(tvb, off, min(5+l, tvb.Remaining(off)), "GRPC Message")
		_, comp := mt.AddUint(hfGRPCComp, tvb, off, 1)
		mt.AddUint(hfGRPCLen, tvb, off+1, 4)
		if tvb.Remaining(off+5) < l {
			mt.AddBytes(hfGRPCMsg, tvb, off+5, tvb.Remaining(off+5))
			break
		}
		msg := tvb.Sub(off+5, l)
		if comp != 0 {
			mt.AddBytes(hfGRPCMsg, msg, 0, l)
		} else {
			dissectProtobuf(msg, mt, 0)
		}
		off += 5 + l
	}
	return tvb.Len()
}

// dissectProtobuf decodes a message without a schema.
func dissectProtobuf(tvb *d.Tvb, tree *d.Node, depth int) int {
	pt := tree
	if depth == 0 {
		pt = tree.AddProtocol(protoPB, tvb, 0, -1)
	}
	raw := tvb.Raw()
	for off := 0; off < len(raw); {
		num, typ, n := protowire.ConsumeTag(raw[off:])
		if n < 0 {
			break
		}
		fn := pt.AddText(tvb, off, n, "Field")
		fn.AddValue(hfPBNumber, nil, 0, 0, d.UintValue(d.FtUint32, uint64(num)))
		fn.AddValue(hfPBWire, nil, 0, 0, d.UintValue(d.FtUint8, uint64(typ)))
		vs := off + n
		vn := protowire.ConsumeFieldValue(num, typ, raw[vs:])
		if vn < 0 {
			fn.SetText("Field %d: malformed", num)
			break
		}
		switch typ {
		case protowire.VarintType:
			v, _ := protowire.ConsumeVarint(raw[vs:])
			fn.AddValue(hfPBVarint, tvb, vs, vn, d.UintValue(d.FtUint64, v))
			fn.SetText("Field %d: %s: %d", num, grpcWireName[typ], v)
		case protowire.Fixed32Type:
			v, _ := protowire.ConsumeFixed32(raw[vs:])
			fn.AddValue(hfPBFixed, tvb, vs, vn, d.UintValue(d.FtUint64, uint64(v)))
			fn.SetText("Field %d: %s: 0x%08x", num, grpcWireName[typ], v)
		case protowire.Fixed64Type:
			v, _ := protowire.ConsumeFixed64(raw[vs:])
			fn.AddValue(hfPBFixed, tvb, vs, vn, d.UintValue(d.FtUint64, v))
			fn.SetText("Field %d: %s: 0x%016x", num, grpcWireName[typ], v)
		case protowire.BytesType:
			b, bn := protowire.ConsumeBytes(raw[vs:])
			ls := vs + (vn - len(b))
			_ = bn
			switch {
			case len(b) > 0 && utf8.Valid(b) && printable(b):
				fn.AddValue(hfPBString, tvb, ls, len(b), d.StringValue(string(b)))
				fn.SetText("Field %d: String: %s", num, string(b))
			case depth < 4 && len(b) > 0 && validMessage(b):
				fn.SetText("Field %d: Message", num)
				dissectProtobuf(tvb.Sub(ls, len(b)), fn, depth+1)
			default:
				fn.AddValue(hfPBBytes, tvb, ls, len(b), d.BytesValue(d.FtBytes, b))
				fn.SetText("Field %d: Bytes (%d)", num, len(b))
			}
		default:
			fn.SetText("Field %d: %s", num, fmt.Sprint(grpcWireName[typ]))
		}
		fn.SetLen(n + vn)
		off = vs + vn
	}
	return tvb.Len()
}

func printable(b []byte) bool {
	for _, r := range string(b) {
		if r < 0x20 && r != '\n' && r != '\t' && r != '\r' || r == 0x7f {
			return false
		}
	}
	return true
}

// validMessage reports whether b parses cleanly as a protobuf message.
func validMessage(b []byte) bool {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 || num == 0 || typ > protowire.Fixed32Type {
			return false
		}
		vn := protowire.ConsumeFieldValue(num, typ, b[n:])
		if vn < 0 {
			return false
		}
		b = b[n+vn:]
	}
	return true
}
