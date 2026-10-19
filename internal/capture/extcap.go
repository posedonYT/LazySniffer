package capture

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
)

// ExtcapArg is a configurable option of an extcap interface.
type ExtcapArg struct {
	Call     string
	Display  string
	Type     string // string, unsigned, long, integer, boolean, boolflag, selector, password, fileselect
	Default  string
	Required bool
	Tooltip  string
	Values   []ExtcapValue
}

// ExtcapValue is a choice of a selector argument.
type ExtcapValue struct{ Value, Display string }

// ExtcapIface is an interface provided by an extcap tool (sshdump, androiddump, …).
type ExtcapIface struct {
	Tool    string // path of the executable
	Name    string // interface value
	Display string
}

// ExtcapDirs lists the directories searched for extcap tools: the
// $WIRESHARK_EXTCAP_DIR override, the user's Wireshark directory and the
// usual install locations (including Homebrew's cellar).
func ExtcapDirs() []string {
	var dirs []string
	add := func(d string) {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			dirs = append(dirs, d)
		}
	}
	if d := os.Getenv("WIRESHARK_EXTCAP_DIR"); d != "" {
		add(d)
	}
	home, _ := os.UserHomeDir()
	add(filepath.Join(home, ".config", "wireshark", "extcap"))
	add(filepath.Join(home, ".local", "lib", "wireshark", "extcap"))
	for _, d := range []string{"/usr/lib/wireshark/extcap", "/usr/lib64/wireshark/extcap", "/usr/lib/x86_64-linux-gnu/wireshark/extcap", "/usr/lib/aarch64-linux-gnu/wireshark/extcap",
		"/usr/local/lib/wireshark/extcap", "/opt/homebrew/lib/wireshark/extcap", "/Applications/Wireshark.app/Contents/MacOS/extcap"} {
		add(d)
	}
	if m, _ := filepath.Glob("/opt/homebrew/Cellar/wireshark/*/libexec/wireshark/extcap"); len(m) > 0 {
		sort.Strings(m)
		add(m[len(m)-1])
	}
	return dirs
}

var kvRe = regexp.MustCompile(`\{([a-z_]+)=([^}]*)\}`)

func parseKV(line string) map[string]string {
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(line, -1) {
		m[x[1]] = x[2]
	}
	return m
}

var (
	extcapMu    sync.Mutex
	extcapCache []ExtcapIface
	extcapDone  bool
)

// ExtcapInterfaces queries every extcap tool for its interfaces (cached).
func ExtcapInterfaces() []ExtcapIface {
	extcapMu.Lock()
	defer extcapMu.Unlock()
	if extcapDone {
		return extcapCache
	}
	extcapDone = true
	seen := map[string]bool{}
	for _, dir := range ExtcapDirs() {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			path := filepath.Join(dir, e.Name())
			if e.IsDir() || seen[e.Name()] {
				continue
			}
			if st, err := os.Stat(path); err != nil || st.Mode()&0o111 == 0 {
				continue
			}
			seen[e.Name()] = true
			out, err := exec.Command(path, "--extcap-interfaces").Output()
			if err != nil {
				continue
			}
			for _, l := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(l, "interface ") {
					kv := parseKV(l)
					if kv["value"] != "" {
						extcapCache = append(extcapCache, ExtcapIface{Tool: path, Name: kv["value"], Display: kv["display"]})
					}
				}
			}
		}
	}
	return extcapCache
}

// ExtcapArgs returns the options of an interface.
func ExtcapArgs(ifc ExtcapIface) ([]ExtcapArg, error) {
	out, err := exec.Command(ifc.Tool, "--extcap-interface", ifc.Name, "--extcap-config").Output()
	if err != nil {
		return nil, err
	}
	var args []ExtcapArg
	byNum := map[string]int{}
	for _, l := range strings.Split(string(out), "\n") {
		kv := parseKV(l)
		switch {
		case strings.HasPrefix(l, "arg "):
			a := ExtcapArg{Call: kv["call"], Display: kv["display"], Type: kv["type"], Default: kv["default"], Tooltip: kv["tooltip"], Required: kv["required"] == "true"}
			byNum[kv["number"]] = len(args)
			args = append(args, a)
		case strings.HasPrefix(l, "value "):
			if i, ok := byNum[kv["arg"]]; ok {
				args[i].Values = append(args[i].Values, ExtcapValue{kv["value"], kv["display"]})
				if kv["default"] == "true" {
					args[i].Default = kv["value"]
				}
			}
		}
	}
	return args, nil
}

// lazyFifo opens a FIFO for reading on first use (the open blocks until the
// extcap tool opens the writing end).
type lazyFifo struct {
	path string
	once sync.Once
	f    *os.File
	err  error
}

func (l *lazyFifo) Read(b []byte) (int, error) {
	l.once.Do(func() { l.f, l.err = os.OpenFile(l.path, os.O_RDONLY, 0) })
	if l.err != nil {
		return 0, l.err
	}
	return l.f.Read(b)
}

func (l *lazyFifo) Close() error {
	if l.f != nil {
		l.f.Close()
	}
	os.Remove(l.path)
	return nil
}

// ExtcapOptions configure one extcap capture.
type ExtcapOptions struct {
	Iface  ExtcapIface
	Args   map[string]string // call (--remote-host) → value
	Filter string
}

// StartExtcap runs an extcap tool and captures the pcap stream it writes
// into a FIFO, like Wireshark does.
func StartExtcap(o ExtcapOptions) (*Live, error) {
	dir, err := os.MkdirTemp("", "lazysniffer-extcap-")
	if err != nil {
		return nil, err
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	args := []string{"--extcap-interface", o.Iface.Name, "--capture", "--fifo", fifo}
	if o.Filter != "" {
		args = append(args, "--extcap-capture-filter", o.Filter)
	}
	var calls []string
	for k := range o.Args {
		calls = append(calls, k)
	}
	sort.Strings(calls)
	for _, k := range calls {
		v := o.Args[k]
		if v == "" {
			continue
		}
		if isFlagCall(o, k) { // boolflag: the option alone when set
			if v == "true" {
				args = append(args, k)
			}
			continue
		}
		args = append(args, k, v)
	}
	cmd := exec.Command(o.Iface.Tool, args...)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	rd := &lazyFifo{path: fifo}
	desc := "extcap " + o.Iface.Name
	waited := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		// If the tool died before opening the FIFO, unblock our reader.
		if f, oerr := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); oerr == nil {
			f.Close()
		}
		waited <- err
	}()
	l, err := StartPipe(rd, desc, func() error {
		err := <-waited
		os.RemoveAll(dir)
		if err != nil && strings.TrimSpace(errBuf.String()) != "" {
			return fmt.Errorf("%s", firstLine(errBuf.String()))
		}
		return err
	})
	if err != nil {
		cmd.Process.Kill()
		os.RemoveAll(dir)
		return nil, err
	}
	l.cmd = cmd
	l.Desc = desc
	return l, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

// isFlagCall reports whether call is a boolflag argument (no value).
func isFlagCall(o ExtcapOptions, call string) bool {
	args, _ := ExtcapArgs(o.Iface)
	for _, a := range args {
		if a.Call == call {
			return a.Type == "boolflag"
		}
	}
	return false
}

var _ = bufio.NewReader
