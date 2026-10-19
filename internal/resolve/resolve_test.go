package resolve

import "testing"

func TestEtherName(t *testing.T) {
	cases := map[string][]byte{
		"Apple_1c:22:01":     {0xa4, 0x83, 0xe7, 0x1c, 0x22, 0x01},
		"Broadcast":          {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"IPv4mcast_00:00:fb": {0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb},
		"":                   {0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	for want, mac := range cases {
		if got := EtherName(mac); got != want {
			t.Errorf("EtherName(%x) = %q, want %q", mac, got, want)
		}
	}
	if s := Service(443, "tcp"); s != "https" {
		t.Errorf("Service(443) = %q", s)
	}
}
