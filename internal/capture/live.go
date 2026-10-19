package capture

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Live is a running capture whose packets are written to Path.
type Live struct {
	Opts   Options
	Path   string
	Events chan Event
	Start  time.Time
	Desc   string // "en0", "ssh host:eth0", "stdin"

	cmd    *exec.Cmd
	once   sync.Once
	done   chan struct{}
	stderr strings.Builder
	mu     sync.Mutex
}

// TempPath returns a fresh capture file path in the temp directory.
func TempPath(label string) string {
	label = strings.Map(func(r rune) rune {
		if r == '/' || r == ' ' || r == ':' || r == ',' {
			return '-'
		}
		return r
	}, label)
	return filepath.Join(os.TempDir(), fmt.Sprintf("lazysniffer_%s_%s.pcapng", label, time.Now().Format("20060102150405")))
}

// HelperCommand returns how to run the capture helper: a lazysniffer-dumpcap
// binary installed next to the executable or in PATH (it may carry capture
// privileges), else this executable's "dumpcap" subcommand.
func HelperCommand() (string, []string) {
	self, err := os.Executable()
	if err == nil {
		cand := filepath.Join(filepath.Dir(self), "lazysniffer-dumpcap")
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand, nil
		}
	}
	if p, err := exec.LookPath("lazysniffer-dumpcap"); err == nil {
		return p, nil
	}
	if self == "" {
		self = os.Args[0]
	}
	return self, []string{"dumpcap"}
}

// StartLive starts the capture helper.
func StartLive(o Options) (*Live, error) {
	if o.Output == "" {
		label := strings.Join(o.Ifaces, "+")
		if o.Replay != "" {
			label = "replay"
		}
		o.Output = TempPath(label)
	}
	bin, pre := HelperCommand()
	cmd := exec.Command(bin, append(pre, o.Args()...)...)
	cmd.Stdout = io.Discard
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	l := &Live{Opts: o, Path: o.Output, Events: make(chan Event, 64), Start: time.Now(), cmd: cmd, done: make(chan struct{})}
	l.Desc = strings.Join(o.Ifaces, ", ")
	if o.Replay != "" {
		l.Desc = "replay of " + filepath.Base(o.Replay)
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go l.readEvents(stderr)
	return l, nil
}

func (l *Live) readEvents(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		var ev Event
		if json.Unmarshal(line, &ev) != nil {
			l.mu.Lock()
			l.stderr.Write(line)
			l.stderr.WriteByte('\n')
			l.mu.Unlock()
			continue
		}
		if ev.Type == "file" && ev.File != "" {
			l.Path = ev.File
		}
		select {
		case l.Events <- ev:
		default:
			if ev.Type != "stats" {
				l.Events <- ev
			}
		}
	}
	err := l.cmd.Wait()
	if err != nil && !l.stopped() {
		l.mu.Lock()
		msg := strings.TrimSpace(l.stderr.String())
		l.mu.Unlock()
		if msg == "" {
			msg = err.Error()
		}
		l.Events <- Event{Type: "error", Msg: msg}
	}
	l.Events <- Event{Type: "exited"}
	close(l.Events)
}

// Done is closed when Stop is called.
func (l *Live) Done() <-chan struct{} { return l.done }

func (l *Live) stopped() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

// Stop asks the helper to finish writing and exit.
func (l *Live) Stop() {
	l.once.Do(func() {
		close(l.done)
		if l.cmd == nil || l.cmd.Process == nil {
			return
		}
		l.cmd.Process.Signal(syscall.SIGTERM)
		go func() {
			time.Sleep(3 * time.Second)
			if l.cmd.ProcessState == nil {
				l.cmd.Process.Kill()
			}
		}()
	})
}

// StartPipe captures a pcap/pcapng byte stream (stdin, a FIFO or a command's
// output) by copying it into a file that the UI follows.
func StartPipe(r io.ReadCloser, desc string, wait func() error) (*Live, error) {
	path := TempPath(desc)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Live{Path: path, Events: make(chan Event, 64), Start: time.Now(), Desc: desc, done: make(chan struct{})}
	go func() {
		defer close(l.Events)
		defer f.Close()
		buf := make([]byte, 256<<10)
		started := false
		var total uint64
		var errMsg string
		for {
			n, err := r.Read(buf)
			if n > 0 {
				if _, werr := f.Write(buf[:n]); werr != nil {
					errMsg = werr.Error()
					break
				}
				total += uint64(n)
				if !started && total >= 24 {
					started = true
					l.Events <- Event{Type: "started", File: path, Ifaces: []string{desc}}
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) && !l.stopped() {
					errMsg = err.Error()
				}
				break
			}
		}
		r.Close()
		if wait != nil {
			if err := wait(); err != nil && !l.stopped() && errMsg == "" {
				errMsg = err.Error()
			}
		}
		if errMsg != "" {
			l.Events <- Event{Type: "error", Msg: errMsg}
		}
		if !started {
			l.Events <- Event{Type: "error", Msg: "the stream ended before any capture data arrived"}
		}
		l.Events <- Event{Type: "stopped", Bytes: total}
		l.Events <- Event{Type: "exited"}
	}()
	return l, nil
}

// SSHOptions describe a remote capture over ssh.
type SSHOptions struct {
	Host    string // user@host, or an alias from ~/.ssh/config
	Iface   string
	Filter  string
	Command string // remote command; empty builds a tcpdump command line
}

// RemoteCommand is the command run on the remote host.
func (s SSHOptions) RemoteCommand() string {
	if s.Command != "" {
		return s.Command
	}
	iface := s.Iface
	if iface == "" {
		iface = "any"
	}
	filter := s.Filter
	if filter == "" {
		filter = "not port 22"
	}
	return fmt.Sprintf("sudo -n tcpdump -U -s 0 -w - -i %s %s", shellQuote(iface), shellQuote(filter))
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// StartSSH runs a capture command on a remote host with the system ssh
// client (so keys, agents and ~/.ssh/config work as usual).
func StartSSH(o SSHOptions) (*Live, error) {
	cmd := exec.Command("ssh", "-o", "BatchMode=yes", "-T", o.Host, o.RemoteCommand())
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	desc := o.Host
	if o.Iface != "" {
		desc += ":" + o.Iface
	}
	l, err := StartPipe(out, "ssh "+desc, func() error {
		err := cmd.Wait()
		if err != nil && strings.TrimSpace(errBuf.String()) != "" {
			return errors.New(strings.TrimSpace(errBuf.String()))
		}
		return err
	})
	if err != nil {
		cmd.Process.Kill()
		return nil, err
	}
	l.cmd = cmd
	l.Desc = "ssh " + desc
	return l, nil
}
