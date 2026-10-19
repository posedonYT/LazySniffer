//go:build darwin

package capture

import (
	"encoding/binary"
	"net"
	"syscall"
)

const rtmIfInfo2 = 0x12

func readCounters() map[string]Counters {
	out := map[string]Counters{}
	b, err := syscall.RouteRIB(syscall.NET_RT_IFLIST2, 0)
	if err != nil {
		return out
	}
	names := map[int]string{}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			names[i.Index] = i.Name
		}
	}
	le := binary.LittleEndian
	for len(b) >= 4 {
		l := int(le.Uint16(b))
		if l == 0 || l > len(b) {
			break
		}
		m := b[:l]
		b = b[l:]
		// struct if_msghdr2 followed by struct if_data64.
		if m[3] != rtmIfInfo2 || len(m) < 112 {
			continue
		}
		idx := int(le.Uint16(m[12:]))
		name, ok := names[idx]
		if !ok {
			continue
		}
		in, outp := le.Uint64(m[56:]), le.Uint64(m[72:])
		ib, ob := le.Uint64(m[96:]), le.Uint64(m[104:])
		out[name] = Counters{Packets: in + outp, Bytes: ib + ob}
	}
	return out
}
