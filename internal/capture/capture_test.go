package capture

import (
	"testing"
	"time"
)

func TestCheckFilter(t *testing.T) {
	if n, err := CheckFilter(1, "tcp port 443 and not host 1.2.3.4"); err != nil || n == 0 {
		t.Fatalf("valid filter: %d %v", n, err)
	}
	if _, err := CheckFilter(1, "tcp prt 443"); err == nil {
		t.Fatal("invalid filter accepted")
	}
	if n, err := CheckFilter(1, ""); err != nil || n != 0 {
		t.Fatal("empty filter")
	}
}

func TestInterfacesAndCounters(t *testing.T) {
	ifs, err := Interfaces()
	if err != nil {
		t.Skip(err)
	}
	if len(ifs) == 0 {
		t.Skip("no interfaces")
	}
	c1 := ReadCounters()
	time.Sleep(200 * time.Millisecond)
	c2 := ReadCounters()
	if len(c1) == 0 || len(c2) == 0 {
		t.Fatalf("no counters: %v", c1)
	}
	for _, i := range ifs[:min(3, len(ifs))] {
		t.Logf("%-10s %-24s up=%v addrs=%v kind=%s packets=%d", i.Name, i.FriendlyName, i.Up, i.Addrs, i.Kind, c2[i.Name].Packets)
	}
}

func TestExtcapRandpkt(t *testing.T) {
	var ifc *ExtcapIface
	for _, i := range ExtcapInterfaces() {
		if i.Name == "randpkt" {
			i := i
			ifc = &i
		}
	}
	if ifc == nil {
		t.Skip("randpktdump (Wireshark extcap) is not installed")
	}
	args, err := ExtcapArgs(*ifc)
	if err != nil || len(args) < 3 || args[0].Call != "--maxbytes" {
		t.Fatalf("args %v %v", args, err)
	}
	l, err := StartExtcap(ExtcapOptions{Iface: *ifc, Args: map[string]string{"--count": "20", "--type": "dns"}})
	if err != nil {
		t.Fatal(err)
	}
	timeout := time.After(10 * time.Second)
	started := false
	for !started {
		select {
		case ev, ok := <-l.Events:
			if !ok {
				t.Fatal("capture ended before starting")
			}
			if ev.Type == "started" {
				started = true
			}
		case <-timeout:
			t.Fatal("no packets from randpktdump")
		}
	}
	l.Stop()
}
