package ui

import (
	"net/netip"
	"time"

	"github.com/poseydon/lazysniffer/internal/capture"
	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/proc"
)

// startProcSampler samples socket owners while a local capture runs.
func (m *App) startProcSampler(l *capture.Live) {
	t := proc.NewTable()
	m.capt.procs = t
	t.Sample()
	go func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for range tick.C {
			select {
			case <-l.Done():
				t.Sample()
				return
			default:
			}
			t.Sample()
		}
	}()
}

func addrPort(a dissect.Address, port uint32) (netip.AddrPort, bool) {
	var ip netip.Addr
	switch a.Type {
	case dissect.AddrIPv4:
		ip = netip.AddrFrom4([4]byte(a.Bytes()))
	case dissect.AddrIPv6:
		ip = netip.AddrFrom16([16]byte(a.Bytes())).Unmap()
	default:
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, uint16(port)), true
}

// processFor looks a frame's flow up in the sampled socket table.
func (m *App) processFor(pi *dissect.PacketInfo) string {
	t := m.capt.procs
	if t == nil {
		return ""
	}
	var p uint8
	switch pi.PortType {
	case dissect.PortTCP:
		p = 6
	case dissect.PortUDP:
		p = 17
	default:
		return ""
	}
	src, ok1 := addrPort(pi.NetSrc, pi.SrcPort)
	dst, ok2 := addrPort(pi.NetDst, pi.DstPort)
	if !ok1 || !ok2 {
		return ""
	}
	if info, ok := t.Lookup(p, src, dst); ok {
		return info.Name
	}
	return ""
}
