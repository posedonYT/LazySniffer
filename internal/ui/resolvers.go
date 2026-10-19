package ui

import (
	"net/netip"
	"sync/atomic"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/dissect/proto"
	"github.com/poseydon/lazysniffer/internal/resolve"
)

// Name resolution switches read by dissectors running on any goroutine.
var (
	resolveMAC   atomic.Bool
	resolveNet   atomic.Bool
	resolvePorts atomic.Bool
	dns          = resolve.NewDNS()
)

func init() {
	proto.EtherResolver = func(mac []byte) string {
		if !resolveMAC.Load() {
			return ""
		}
		return resolve.EtherName(mac)
	}
	proto.HostResolver = func(a dissect.Address) string {
		if !resolveNet.Load() {
			return ""
		}
		return hostOf(a)
	}
	proto.PortResolver = func(port uint32, transport string) string {
		if !resolvePorts.Load() {
			return ""
		}
		return resolve.Service(port, transport)
	}
	etherName = resolve.EtherName
}

func hostOf(a dissect.Address) string {
	var ip netip.Addr
	switch a.Type {
	case dissect.AddrIPv4:
		ip = netip.AddrFrom4([4]byte(a.Bytes()))
	case dissect.AddrIPv6:
		ip = netip.AddrFrom16([16]byte(a.Bytes()))
	default:
		return ""
	}
	if s := dns.Static(ip); s != "" {
		return s
	}
	return dns.Name(ip)
}

// applyResolution pushes the config switches to the dissectors.
func (m *App) applyResolution() {
	resolveMAC.Store(m.cfg.ResolveMAC)
	resolveNet.Store(m.cfg.ResolveNetwork)
	resolvePorts.Store(m.cfg.ResolvePorts)
}
