package difftest

import (
	"testing"

	"github.com/poseydon/lazysniffer/internal/pcapio"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func TestWLAN(t *testing.T) {
	compare(t, write2(t, pcapio.LinkIEEE80211Radiotap, g.SampleWLAN()), "", []string{
		"radiotap.version", "radiotap.length", "radiotap.datarate", "radiotap.channel.freq", "radiotap.dbm_antsignal", "radiotap.flags",
		"wlan.fc.type", "wlan.fc.subtype", "wlan.fc.type_subtype", "wlan.fc.tods", "wlan.fc.fromds", "wlan.fc.retry", "wlan.fc.protected", "wlan.fc.ds",
		"wlan.duration", "wlan.ra", "wlan.ta", "wlan.da", "wlan.sa", "wlan.bssid", "wlan.seq", "wlan.frag", "wlan.qos.priority",
		"wlan.fixed.beacon", "wlan.fixed.capabilities", "wlan.ssid", "wlan.tag.number", "wlan.tag.length", "wlan.ds.current_channel",
		"wlan.fixed.auth.alg", "wlan.fixed.auth_seq", "wlan.fixed.status_code", "wlan.fixed.reason_code", "wlan.supported_rates",
		"ip.src", "ip.dst", "udp.srcport",
	})
}

func write2(t *testing.T, link pcapio.LinkType, pkts []g.Packet) string {
	return g.WritePcapngLink(t, link, pkts)
}
