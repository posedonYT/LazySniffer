package capture

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// DefaultInterface returns the interface that carries the default route
// ("" when unknown).
func DefaultInterface() string {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("route", "-n", "get", "default").Output()
		if err != nil {
			return ""
		}
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "interface:" {
				return f[1]
			}
		}
	case "linux":
		f, err := os.Open("/proc/net/route")
		if err != nil {
			return ""
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			if c := strings.Fields(sc.Text()); len(c) > 2 && c[1] == "00000000" {
				return c[0]
			}
		}
	}
	return ""
}
