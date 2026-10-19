package capture

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket/pcap"
)

// Check is one diagnostic result.
type Check struct {
	Name string
	OK   bool
	Info string
	Fix  string
}

// CanCapture reports whether this process (or the helper) can open
// capture devices, with a hint on how to fix it.
func CanCapture() (bool, string) {
	for _, c := range Doctor() {
		if c.Name == "Capture permission" {
			return c.OK, c.Fix
		}
	}
	return false, ""
}

// Doctor inspects the environment for live capture and deep mode.
func Doctor() []Check {
	var out []Check
	out = append(out, Check{Name: "libpcap", OK: true, Info: pcap.Version()})
	ok, info, fix := capturePermission()
	out = append(out, Check{Name: "Capture permission", OK: ok, Info: info, Fix: fix})
	bin, pre := HelperCommand()
	out = append(out, Check{Name: "Capture helper", OK: true, Info: strings.TrimSpace(bin + " " + strings.Join(pre, " "))})
	if ifs, err := Interfaces(); err == nil {
		up := 0
		for _, i := range ifs {
			if i.Up {
				up++
			}
		}
		out = append(out, Check{Name: "Interfaces", OK: len(ifs) > 0, Info: fmt.Sprintf("%d found, %d up", len(ifs), up)})
	} else {
		out = append(out, Check{Name: "Interfaces", OK: false, Info: err.Error()})
	}
	for _, tool := range []string{"sharkd", "tshark"} {
		if p, err := exec.LookPath(tool); err == nil {
			out = append(out, Check{Name: "Deep mode: " + tool, OK: true, Info: p})
		} else {
			out = append(out, Check{Name: "Deep mode: " + tool, OK: false, Info: "not installed",
				Fix: "optional: install Wireshark for 3000+ extra dissectors (brew install wireshark / apt install tshark)"})
		}
	}
	if _, err := exec.LookPath("ssh"); err == nil {
		out = append(out, Check{Name: "Remote capture (ssh)", OK: true, Info: "available"})
	}
	return out
}

func capturePermission() (bool, string, string) {
	if os.Geteuid() == 0 {
		return true, "running as root", ""
	}
	switch runtime.GOOS {
	case "darwin":
		devs, _ := filepath.Glob("/dev/bpf*")
		for _, d := range devs {
			f, err := os.OpenFile(d, os.O_RDWR, 0)
			if err == nil {
				f.Close()
				return true, "BPF devices are accessible (" + d + ")", ""
			}
			if !os.IsPermission(err) {
				continue // busy device; try the next one
			}
		}
		info := "no read/write access to /dev/bpf*"
		if inGroup("access_bpf") {
			info += " (you are in access_bpf; the permissions daemon may not have run yet)"
		}
		return false, info, "run `sudo lazysniffer setup` once (grants the access_bpf group BPF access, like Wireshark's ChmodBPF), or start lazysniffer with sudo"
	case "linux":
		if hasCapNetRaw() {
			return true, "process has CAP_NET_RAW", ""
		}
		if bin, pre := HelperCommand(); len(pre) == 0 {
			if out, err := exec.Command("getcap", bin).Output(); err == nil && strings.Contains(string(out), "cap_net_raw") {
				return true, "helper has capabilities: " + strings.TrimSpace(string(out)), ""
			}
		}
		return false, "no CAP_NET_RAW", "run `sudo lazysniffer setup` once (installs lazysniffer-dumpcap with cap_net_raw,cap_net_admin), or start lazysniffer with sudo"
	}
	return false, "unsupported platform", "run as root"
}

func inGroup(name string) bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return false
	}
	ids, _ := u.GroupIds()
	for _, id := range ids {
		if id == g.Gid {
			return true
		}
	}
	return false
}

func hasCapNetRaw() bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
			return err == nil && v&(1<<13) != 0
		}
	}
	return false
}
