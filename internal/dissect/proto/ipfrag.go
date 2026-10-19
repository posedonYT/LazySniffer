package proto

import (
	"fmt"
	"sort"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

// IPDefragment enables IPv4/IPv6 fragment reassembly (ip.defragment).
var IPDefragment = true

type ipFragKey struct {
	src, dst [16]byte
	id       uint32
	proto    uint8
}

type ipFragFrame struct {
	in   uint32         // frame where the datagram was reassembled
	done *d.Reassembled // set on the frame that completed it
}

type fragFields struct {
	fragments, fragment, count, length, data, in *d.FieldDef
	name                                         string
}

var (
	ipFragFields = fragFields{
		fragments: protoIP.Field("ip.fragments", "IPv4 Fragments", d.FtNone),
		fragment:  protoIP.Field("ip.fragment", "IPv4 Fragment", d.FtFrameNum),
		count:     protoIP.Field("ip.fragment.count", "Fragment count", d.FtUint32),
		length:    protoIP.Field("ip.reassembled.length", "Reassembled IPv4 length", d.FtUint32),
		data:      protoIP.Field("ip.reassembled.data", "Reassembled IPv4 data", d.FtBytes),
		in:        protoIP.Field("ip.reassembled_in", "Reassembled IPv4 in frame", d.FtFrameNum),
		name:      "IPv4",
	}
	ipv6FragFields = fragFields{
		fragments: protoIPv6.Field("ipv6.fragments", "IPv6 Fragments", d.FtNone),
		fragment:  protoIPv6.Field("ipv6.fragment", "IPv6 Fragment", d.FtFrameNum),
		count:     protoIPv6.Field("ipv6.fragment.count", "Fragment count", d.FtUint32),
		length:    protoIPv6.Field("ipv6.reassembled.length", "Reassembled IPv6 length", d.FtUint32),
		data:      protoIPv6.Field("ipv6.reassembled.data", "Reassembled IPv6 data", d.FtBytes),
		in:        protoIPv6.Field("ipv6.reassembled_in", "Reassembled IPv6 in frame", d.FtFrameNum),
		name:      "IPv6",
	}
)

// defragment feeds a fragment to the reassembler (first pass) and returns
// the reassembled payload when this frame completes the datagram. On other
// fragments it returns nil and the frame that completed it (0 if never).
func defragment(pi *d.PacketInfo, p *d.Proto, ff *fragFields, key ipFragKey, payload *d.Tvb, off int, more bool, tree *d.Node) (*d.Tvb, uint32) {
	sess := pi.Sess
	if !pi.Visited {
		sets, _ := sess.ProtoState(p).(map[ipFragKey]*d.FragSet)
		if sets == nil {
			sets = map[ipFragKey]*d.FragSet{}
			sess.SetProtoState(p, sets)
		}
		set := sets[key]
		if set == nil {
			set = &d.FragSet{}
			sets[key] = set
		}
		if set.Add(pi.Ref(payload, 0, payload.Len(), off), !more) {
			delete(sets, key)
			frags := append([]d.FragRef(nil), set.Frags...)
			sort.SliceStable(frags, func(i, j int) bool { return frags[i].Pos < frags[j].Pos })
			done := &d.Reassembled{Frags: frags, Total: set.Total}
			sess.SetFrameData(p, pi.Num, 0, &ipFragFrame{in: pi.Num, done: done})
			for _, fr := range done.Frames() {
				if fr != pi.Num {
					sess.SetFrameData(p, fr, 0, &ipFragFrame{in: pi.Num})
				}
			}
		}
	}
	rec, _ := sess.FrameData(p, pi.Num, 0).(*ipFragFrame)
	if rec == nil {
		return nil, 0
	}
	if rec.done == nil {
		tree.AddGenerated(ff.in, d.Value{U: uint64(rec.in)}).SetLink(rec.in)
		return nil, rec.in
	}
	buf := sess.Assemble(rec.done.Frags, rec.done.Total)
	tvb := pi.AddSource("Reassembled "+ff.name, buf)
	addFragmentTree(tree, ff, rec.done, tvb)
	return tvb, pi.Num
}

func addFragmentTree(tree *d.Node, ff *fragFields, r *d.Reassembled, tvb *d.Tvb) {
	var parts []string
	for _, f := range r.Frags {
		parts = append(parts, fmt.Sprintf("#%d(%d)", f.Frame, f.Len))
	}
	ft := tree.AddValue(ff.fragments, tvb, 0, tvb.Len(), d.Value{}).SetGenerated()
	ft.SetText("[%d %s Fragments (%d bytes): %s]", len(r.Frags), ff.name, r.Total, strings.Join(parts, ", "))
	for _, f := range r.Frags {
		n := ft.AddValue(ff.fragment, tvb, int(f.Pos), int(f.Len), d.Value{U: uint64(f.Frame)})
		n.SetText("[Frame: %d, payload: %d-%d (%d bytes)]", f.Frame, f.Pos, f.Pos+f.Len-1, f.Len).SetLink(f.Frame)
	}
	ft.AddGenerated(ff.count, d.Value{U: uint64(len(r.Frags))})
	ft.AddGenerated(ff.length, d.Value{U: uint64(r.Total)})
	ft.AddValue(ff.data, tvb, 0, tvb.Len(), d.Value{B: tvb.Raw()}).SetGenerated()
}
