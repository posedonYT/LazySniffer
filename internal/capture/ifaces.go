package capture

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/gopacket/gopacket/pcap"
)

// pcap_if flags.
const (
	ifLoopback     = 0x01
	ifUp           = 0x02
	ifRunning      = 0x04
	ifWireless     = 0x08
	ifConnMask     = 0x30
	ifConnected    = 0x10
	ifDisconnected = 0x20
)

// Iface is a capturable interface.
type Iface struct {
	Name         string
	FriendlyName string // "Wi-Fi", from the OS when available
	Description  string
	Addrs        []string
	Up           bool
	Running      bool
	Loopback     bool
	Wireless     bool
	Connected    bool // link up (or not applicable)
	Kind         string
}

// Label is the name shown in interface lists.
func (i Iface) Label() string {
	f := strings.TrimSpace(strings.ReplaceAll(i.FriendlyName, "("+i.Name+")", ""))
	if f != "" && f != i.Name {
		return i.Name + " (" + f + ")"
	}
	return i.Name
}

// Interfaces lists capture devices. It does not need capture privileges.
func Interfaces() ([]Iface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	friendly := friendlyNames()
	var out []Iface
	for _, d := range devs {
		ifc := Iface{
			Name: d.Name, Description: d.Description,
			Up: d.Flags&ifUp != 0, Running: d.Flags&ifRunning != 0,
			Loopback: d.Flags&ifLoopback != 0, Wireless: d.Flags&ifWireless != 0,
			Connected: d.Flags&ifConnMask != ifDisconnected,
		}
		ifc.FriendlyName = friendly[d.Name]
		for _, a := range d.Addresses {
			if a.IP != nil {
				ifc.Addrs = append(ifc.Addrs, a.IP.String())
			}
		}
		ifc.Kind = kindOf(ifc)
		out = append(out, ifc)
	}
	// Useful interfaces first: up, with addresses, not pseudo devices.
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out, nil
}

func kindOf(i Iface) string {
	n := i.Name
	switch {
	case i.Loopback:
		return "loopback"
	case strings.HasPrefix(n, "utun") || strings.HasPrefix(n, "tun") || strings.HasPrefix(n, "wg") || strings.HasPrefix(n, "ppp") || strings.HasPrefix(n, "ipsec"):
		return "vpn"
	case i.Wireless || strings.HasPrefix(n, "wl"):
		return "wireless"
	case strings.HasPrefix(n, "en") || strings.HasPrefix(n, "eth"):
		return "ethernet"
	case strings.HasPrefix(n, "bridge") || strings.HasPrefix(n, "br-") || strings.HasPrefix(n, "docker") || strings.HasPrefix(n, "veth"):
		return "bridge"
	case n == "any" || n == "pktap":
		return "pseudo"
	case strings.HasPrefix(n, "bluetooth"):
		return "bluetooth"
	case strings.HasPrefix(n, "usbmon"):
		return "usb"
	}
	return "other"
}

func rank(i Iface) int {
	r := 0
	if !i.Up {
		r += 100
	}
	if len(i.Addrs) == 0 {
		r += 10
	}
	switch i.Kind {
	case "wireless", "ethernet":
	case "vpn":
		r += 2
	case "loopback":
		r += 3
	case "pseudo":
		r += 1
	default:
		r += 5
	}
	return r
}

var (
	friendlyOnce sync.Once
	friendlyMap  map[string]string
)

// friendlyNames maps device names to the OS's human names ("en0" → "Wi-Fi").
func friendlyNames() map[string]string {
	friendlyOnce.Do(func() {
		friendlyMap = map[string]string{}
		if runtime.GOOS != "darwin" {
			return
		}
		out, err := exec.Command("networksetup", "-listallhardwareports").Output()
		if err != nil {
			return
		}
		var port string
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "Hardware Port: "):
				port = strings.TrimPrefix(line, "Hardware Port: ")
			case strings.HasPrefix(line, "Device: ") && port != "":
				friendlyMap[strings.TrimPrefix(line, "Device: ")] = port
			}
		}
		friendlyMap["lo0"] = "Loopback"
	})
	return friendlyMap
}

// LocalAddrs returns the host's own IP addresses (to tell in from out).
func LocalAddrs() map[string]bool {
	out := map[string]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			out[ipn.IP.String()] = true
		}
	}
	return out
}
