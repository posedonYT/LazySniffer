package stats

import (
	"context"
	"sort"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/store"
)

// WLANNet is a BSS seen in an 802.11 capture.
type WLANNet struct {
	BSSID     string
	SSID      string
	Channel   int
	Beacons   int
	Probes    int
	Data      int
	Mgmt      int
	Control   int
	Retries   int
	Packets   int
	SigMin    int
	SigMax    int
	Encrypted bool
	First     uint32
}

// WLANTraffic summarizes the access points and their traffic.
func WLANTraffic(ctx context.Context, c *store.Capture) ([]*WLANNet, error) {
	names := []string{"wlan.bssid", "wlan.ssid", "wlan.ds.current_channel", "radiotap.dbm_antsignal", "wlan.fc.type", "wlan.fc.type_subtype", "wlan.fc.retry",
		"wlan.fc.protected", "wlan.rsn.version", "radiotap.channel.freq"}
	fd := make([]*dissect.FieldDef, len(names))
	want := make([]bool, dissect.NumFields())
	for i, n := range names {
		fd[i] = dissect.LookupField(n)
		want[fd[i].ID] = true
	}
	parts := make([]map[string]*WLANNet, engine.Workers())
	for i := range parts {
		parts[i] = map[string]*WLANNet{}
	}
	err := engine.Each(ctx, c, dissect.Options{Want: want}, engine.AllFrames(c), func(w int, num uint32, pi *dissect.PacketInfo) {
		b, ok := pi.Tree.First(fd[0])
		if !ok {
			return
		}
		key := dissect.FormatEther(b.V.B)
		if key == "ff:ff:ff:ff:ff:ff" {
			return
		}
		n := parts[w][key]
		if n == nil {
			n = &WLANNet{BSSID: key, SigMin: 1, SigMax: -200, First: num}
			parts[w][key] = n
		}
		n.Packets++
		n.First = min(n.First, num)
		typ, _ := pi.Tree.First(fd[4])
		sub, _ := pi.Tree.First(fd[5])
		switch typ.V.U {
		case 0:
			n.Mgmt++
			switch sub.V.U & 0xf {
			case 8:
				n.Beacons++
			case 4, 5:
				n.Probes++
			}
		case 1:
			n.Control++
		case 2:
			n.Data++
		}
		if v, ok := pi.Tree.First(fd[1]); ok && len(v.V.B) > 0 && n.SSID == "" {
			n.SSID = string(v.V.B)
		}
		if v, ok := pi.Tree.First(fd[2]); ok {
			n.Channel = int(v.V.U)
		}
		if v, ok := pi.Tree.First(fd[3]); ok {
			sig := int(int8(v.V.U))
			if v.V.T.IsSigned() {
				sig = int(v.V.Int())
			}
			n.SigMin, n.SigMax = min(n.SigMin, sig), max(n.SigMax, sig)
		}
		if v, ok := pi.Tree.First(fd[6]); ok && v.V.U != 0 {
			n.Retries++
		}
		if _, ok := pi.Tree.First(fd[8]); ok {
			n.Encrypted = true
		}
		if v, ok := pi.Tree.First(fd[7]); ok && v.V.U != 0 && typ.V.U == 2 {
			n.Encrypted = true
		}
	})
	if err != nil {
		return nil, err
	}
	merged := map[string]*WLANNet{}
	for _, p := range parts {
		for k, n := range p {
			m := merged[k]
			if m == nil {
				merged[k] = n
				continue
			}
			m.Packets += n.Packets
			m.Beacons += n.Beacons
			m.Probes += n.Probes
			m.Data += n.Data
			m.Mgmt += n.Mgmt
			m.Control += n.Control
			m.Retries += n.Retries
			m.First = min(m.First, n.First)
			m.SigMin, m.SigMax = min(m.SigMin, n.SigMin), max(m.SigMax, n.SigMax)
			m.Encrypted = m.Encrypted || n.Encrypted
			if m.SSID == "" {
				m.SSID = n.SSID
			}
			if m.Channel == 0 {
				m.Channel = n.Channel
			}
		}
	}
	out := make([]*WLANNet, 0, len(merged))
	for _, n := range merged {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Packets > out[j].Packets })
	return out, nil
}
