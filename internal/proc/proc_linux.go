//go:build linux

package proc

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Supported reports whether socket sampling works on this platform.
const Supported = true

// Sample reads the socket tables and the processes owning the sockets.
func (t *Table) Sample() error {
	owners := map[uint64]Info{}
	dirs, _ := filepath.Glob("/proc/[0-9]*/fd")
	for _, d := range dirs {
		pidStr := filepath.Base(filepath.Dir(d))
		pid, _ := strconv.Atoi(pidStr)
		ents, err := os.ReadDir(d)
		if err != nil {
			continue // other users' processes need privileges
		}
		var name string
		for _, e := range ents {
			link, err := os.Readlink(filepath.Join(d, e.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
			if err != nil {
				continue
			}
			if name == "" {
				b, _ := os.ReadFile(filepath.Join("/proc", pidStr, "comm"))
				name = strings.TrimSpace(string(b))
			}
			owners[inode] = Info{PID: int32(pid), Name: name}
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, src := range []struct {
		path  string
		proto uint8
	}{{"/proc/net/tcp", 6}, {"/proc/net/tcp6", 6}, {"/proc/net/udp", 17}, {"/proc/net/udp6", 17}} {
		f, err := os.Open(src.path)
		if err != nil {
			continue
		}
		for _, s := range ParseNet(f) {
			if info, ok := owners[s.Inode]; ok {
				t.add(src.proto, s, info)
			}
		}
		f.Close()
	}
	return nil
}
