//go:build linux

package capture

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func readCounters() map[string]Counters {
	out := map[string]Counters{}
	dirs, _ := filepath.Glob("/sys/class/net/*/statistics")
	read := func(dir, name string) uint64 {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return 0
		}
		v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		return v
	}
	for _, d := range dirs {
		iface := filepath.Base(filepath.Dir(d))
		out[iface] = Counters{
			Packets: read(d, "rx_packets") + read(d, "tx_packets"),
			Bytes:   read(d, "rx_bytes") + read(d, "tx_bytes"),
		}
	}
	return out
}
