package capture

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gopacket/gopacket/pcap"

	"github.com/poseydon/lazysniffer/internal/pcapio"
)

// Event is a JSON line the helper writes to stderr for the UI.
type Event struct {
	Type    string   `json:"type"` // started, stats, file, error, stopped
	Msg     string   `json:"msg,omitempty"`
	File    string   `json:"file,omitempty"`
	Ifaces  []string `json:"ifaces,omitempty"`
	Packets uint64   `json:"packets,omitempty"`
	Dropped uint64   `json:"dropped,omitempty"`
	Bytes   uint64   `json:"bytes,omitempty"`
	Perm    bool     `json:"perm,omitempty"` // a permission problem
	Elapsed float64  `json:"elapsed,omitempty"`
}

// Options of a capture run (dumpcap command line).
type Options struct {
	Ifaces      []string
	Filter      string
	SnapLen     int
	BufferMB    int
	NoPromisc   bool
	Monitor     bool
	PKTAP       bool // macOS: per-packet process info
	Output      string
	Replay      string  // read packets from a file instead of capturing
	ReplaySpeed float64 // 0 = as fast as possible, 1 = real time
	StopAfter   time.Duration
	StopPackets uint64
	StopBytes   uint64
	RingSize    uint64 // bytes per file (0 = no ring buffer)
	RingFiles   int
	RingTime    time.Duration
	Quiet       bool
}

// Args renders options as helper command-line arguments.
func (o Options) Args() []string {
	var a []string
	for _, i := range o.Ifaces {
		a = append(a, "-i", i)
	}
	if o.Filter != "" {
		a = append(a, "-f", o.Filter)
	}
	if o.SnapLen > 0 {
		a = append(a, "-s", strconv.Itoa(o.SnapLen))
	}
	if o.BufferMB > 0 {
		a = append(a, "-B", strconv.Itoa(o.BufferMB))
	}
	if o.NoPromisc {
		a = append(a, "-p")
	}
	if o.Monitor {
		a = append(a, "-I")
	}
	if o.PKTAP {
		a = append(a, "-k")
	}
	if o.Replay != "" {
		a = append(a, "-r", o.Replay, "--speed", strconv.FormatFloat(o.ReplaySpeed, 'g', -1, 64))
	}
	if o.StopAfter > 0 {
		a = append(a, "-a", "duration:"+strconv.Itoa(int(o.StopAfter.Seconds())))
	}
	if o.StopPackets > 0 {
		a = append(a, "-c", strconv.FormatUint(o.StopPackets, 10))
	}
	if o.StopBytes > 0 {
		a = append(a, "-a", "filesize:"+strconv.FormatUint(o.StopBytes/1000, 10))
	}
	if o.RingSize > 0 {
		a = append(a, "-b", "filesize:"+strconv.FormatUint(o.RingSize/1000, 10))
	}
	if o.RingFiles > 0 {
		a = append(a, "-b", "files:"+strconv.Itoa(o.RingFiles))
	}
	if o.RingTime > 0 {
		a = append(a, "-b", "duration:"+strconv.Itoa(int(o.RingTime.Seconds())))
	}
	a = append(a, "-w", o.Output)
	return a
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

// ParseArgs parses a dumpcap-style command line.
func ParseArgs(args []string) (Options, error) {
	var o Options
	fs := flag.NewFlagSet("dumpcap", flag.ContinueOnError)
	var ifaces, autostop, ring multiFlag
	fs.Var(&ifaces, "i", "interface (repeatable)")
	fs.StringVar(&o.Filter, "f", "", "capture filter (BPF syntax)")
	fs.IntVar(&o.SnapLen, "s", 262144, "snapshot length")
	fs.IntVar(&o.BufferMB, "B", 4, "kernel buffer size in MB")
	fs.BoolVar(&o.NoPromisc, "p", false, "don't capture in promiscuous mode")
	fs.BoolVar(&o.Monitor, "I", false, "capture in monitor mode (Wi-Fi)")
	fs.BoolVar(&o.PKTAP, "k", false, "macOS: add process information (PKTAP)")
	fs.StringVar(&o.Output, "w", "", "output pcapng file (- for stdout)")
	fs.StringVar(&o.Replay, "r", "", "replay a capture file instead of capturing")
	fs.Float64Var(&o.ReplaySpeed, "speed", 1, "replay speed (0 = as fast as possible)")
	fs.Uint64Var(&o.StopPackets, "c", 0, "stop after this many packets")
	fs.Var(&autostop, "a", "autostop condition: duration:SEC, filesize:KB")
	fs.Var(&ring, "b", "ring buffer: filesize:KB, files:N, duration:SEC")
	fs.BoolVar(&o.Quiet, "q", false, "no stats on stderr")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	o.Ifaces = ifaces
	for _, a := range autostop {
		k, v, _ := strings.Cut(a, ":")
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return o, fmt.Errorf("bad -a %q", a)
		}
		switch k {
		case "duration":
			o.StopAfter = time.Duration(n) * time.Second
		case "filesize":
			o.StopBytes = n * 1000
		case "packets":
			o.StopPackets = n
		default:
			return o, fmt.Errorf("unknown autostop condition %q", k)
		}
	}
	for _, b := range ring {
		k, v, _ := strings.Cut(b, ":")
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return o, fmt.Errorf("bad -b %q", b)
		}
		switch k {
		case "filesize":
			o.RingSize = n * 1000
		case "files":
			o.RingFiles = int(n)
		case "duration":
			o.RingTime = time.Duration(n) * time.Second
		default:
			return o, fmt.Errorf("unknown ring buffer option %q", k)
		}
	}
	if o.Output == "" {
		return o, errors.New("an output file is required (-w)")
	}
	if len(o.Ifaces) == 0 && o.Replay == "" {
		return o, errors.New("no interface given (-i)")
	}
	return o, nil
}

// dltToLinkType converts a libpcap DLT_ value to a LINKTYPE_ value for files.
func dltToLinkType(dlt int) pcapio.LinkType {
	switch dlt {
	case 12, 14:
		return pcapio.LinkRaw
	case 149:
		if runtime.GOOS == "darwin" {
			return pcapio.LinkPKTAP
		}
	case 11:
		return 100 // ATM RFC 1483
	}
	return pcapio.LinkType(dlt)
}

type packet struct {
	iface uint32
	ts    int64
	orig  uint32
	data  []byte
}

// emitter writes JSON events to stderr.
type emitter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (e *emitter) send(ev Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enc.Encode(ev)
}

// RunDumpcap is the capture helper's main function. It returns the process
// exit code.
func RunDumpcap(args []string) int {
	em := &emitter{enc: json.NewEncoder(os.Stderr)}
	o, err := ParseArgs(args)
	if err != nil {
		em.send(Event{Type: "error", Msg: err.Error()})
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	if err := runCapture(ctx, o, em); err != nil {
		perm := strings.Contains(err.Error(), "ermission") || strings.Contains(err.Error(), "Operation not permitted")
		em.send(Event{Type: "error", Msg: err.Error(), Perm: perm})
		return 1
	}
	return 0
}

type source struct {
	name  string
	link  pcapio.LinkType
	snap  int
	h     *pcap.Handle
	stats func() (recv, drop uint64)
}

func runCapture(ctx context.Context, o Options, em *emitter) error {
	var sources []*source
	if o.Replay != "" {
		f, err := pcapio.Open(o.Replay)
		if err != nil {
			return err
		}
		defer f.Close()
		return replay(ctx, o, f, em)
	}
	for _, name := range o.Ifaces {
		src, err := openLive(name, o)
		if err != nil {
			for _, s := range sources {
				s.h.Close()
			}
			return fmt.Errorf("%s: %w", name, err)
		}
		sources = append(sources, src)
	}
	defer func() {
		for _, s := range sources {
			s.h.Close()
		}
	}()
	ifaces := make([]pcapio.Interface, len(sources))
	for i, s := range sources {
		ifaces[i] = pcapio.Interface{LinkType: s.link, SnapLen: uint32(s.snap), Name: s.name, Filter: o.Filter, OS: runtime.GOOS, FCSLen: -1}
	}
	out, err := newRotator(o, ifaces)
	if err != nil {
		return err
	}
	defer out.close()

	pkts := make(chan packet, 4096)
	var wg sync.WaitGroup
	for i, s := range sources {
		wg.Add(1)
		go func(idx uint32, s *source) {
			defer wg.Done()
			for ctx.Err() == nil {
				data, ci, err := s.h.ReadPacketData()
				if err != nil {
					if errors.Is(err, pcap.NextErrorTimeoutExpired) {
						continue
					}
					if errors.Is(err, io.EOF) || errors.Is(err, pcap.NextErrorNoMorePackets) {
						return
					}
					em.send(Event{Type: "error", Msg: s.name + ": " + err.Error()})
					return
				}
				select {
				case pkts <- packet{idx, ci.Timestamp.UnixNano(), uint32(ci.Length), data}:
				case <-ctx.Done():
					return
				}
			}
		}(uint32(i), s)
	}
	go func() { wg.Wait(); close(pkts) }()

	names := make([]string, len(sources))
	for i, s := range sources {
		names[i] = s.name
	}
	em.send(Event{Type: "started", File: out.current, Ifaces: names})
	return pump(ctx, o, out, pkts, em, func() (uint64, uint64) {
		var r, d uint64
		for _, s := range sources {
			if st, err := s.h.Stats(); err == nil {
				r += uint64(st.PacketsReceived)
				d += uint64(st.PacketsDropped + st.PacketsIfDropped)
			}
		}
		return r, d
	})
}

func openLive(name string, o Options) (*source, error) {
	dev := name
	in, err := pcap.NewInactiveHandle(dev)
	if err != nil {
		return nil, err
	}
	defer in.CleanUp()
	in.SetSnapLen(o.SnapLen)
	in.SetPromisc(!o.NoPromisc)
	in.SetTimeout(100 * time.Millisecond)
	in.SetImmediateMode(true)
	if o.BufferMB > 0 {
		in.SetBufferSize(o.BufferMB << 20)
	}
	if o.Monitor {
		if err := in.SetRFMon(true); err != nil {
			return nil, fmt.Errorf("monitor mode: %w", err)
		}
	}
	if o.PKTAP {
		if err := setWantPktap(in); err != nil {
			return nil, fmt.Errorf("PKTAP: %w", err)
		}
	}
	h, err := in.Activate()
	if err != nil {
		return nil, err
	}
	if o.Filter != "" {
		if err := h.SetBPFFilter(o.Filter); err != nil {
			h.Close()
			return nil, fmt.Errorf("capture filter: %w", err)
		}
	}
	return &source{name: name, link: dltToLinkType(int(h.LinkType())), snap: o.SnapLen, h: h}, nil
}

// pump writes packets until a stop condition or cancellation.
func pump(ctx context.Context, o Options, out *rotator, pkts <-chan packet, em *emitter, stats func() (uint64, uint64)) error {
	start := time.Now()
	var count, bytes atomic.Uint64
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	flush := time.NewTicker(50 * time.Millisecond)
	defer flush.Stop()
	report := func(final bool) {
		recv, drop := uint64(0), uint64(0)
		if stats != nil {
			recv, drop = stats()
		}
		_ = recv
		typ := "stats"
		if final {
			typ = "stopped"
		}
		if !o.Quiet || final {
			em.send(Event{Type: typ, Packets: count.Load(), Bytes: bytes.Load(), Dropped: drop, Elapsed: time.Since(start).Seconds(), File: out.current})
		}
	}
	defer report(true)
	var stopTimer <-chan time.Time
	if o.StopAfter > 0 {
		stopTimer = time.After(o.StopAfter)
	}
	for {
		select {
		case <-ctx.Done():
			return out.flush()
		case <-stopTimer:
			return out.flush()
		case <-flush.C:
			if err := out.flush(); err != nil {
				return err
			}
		case <-tick.C:
			report(false)
			if o.RingTime > 0 && time.Since(out.opened) >= o.RingTime {
				if err := out.rotate(); err != nil {
					return err
				}
				em.send(Event{Type: "file", File: out.current})
			}
		case p, ok := <-pkts:
			if !ok {
				return out.flush()
			}
			if err := out.write(p); err != nil {
				return err
			}
			count.Add(1)
			bytes.Add(uint64(len(p.data)))
			if o.StopPackets > 0 && count.Load() >= o.StopPackets {
				return out.flush()
			}
			if o.StopBytes > 0 && bytes.Load() >= o.StopBytes {
				return out.flush()
			}
			if o.RingSize > 0 && out.size >= o.RingSize {
				if err := out.rotate(); err != nil {
					return err
				}
				em.send(Event{Type: "file", File: out.current})
			}
		}
	}
}

// replay feeds a capture file through the live pipeline (for demos and tests).
func replay(ctx context.Context, o Options, f *pcapio.File, em *emitter) error {
	out, err := newRotator(o, f.Interfaces)
	if err != nil {
		return err
	}
	defer out.close()
	pkts := make(chan packet, 1024)
	go func() {
		defer close(pkts)
		var first int64
		start := time.Now()
		for ctx.Err() == nil {
			rec, err := f.Next()
			if err != nil {
				return
			}
			ts := rec.TS
			if first == 0 {
				first = ts
			}
			if o.ReplaySpeed > 0 {
				due := start.Add(time.Duration(float64(ts-first) / o.ReplaySpeed))
				if d := time.Until(due); d > 0 {
					select {
					case <-time.After(d):
					case <-ctx.Done():
						return
					}
				}
				ts = time.Now().UnixNano()
			}
			data := append([]byte(nil), f.Data(rec.DataOff, rec.CapLen)...)
			select {
			case pkts <- packet{rec.Iface, ts, rec.OrigLen, data}:
			case <-ctx.Done():
				return
			}
		}
	}()
	names := make([]string, len(f.Interfaces))
	for i, ifc := range f.Interfaces {
		names[i] = ifc.Name
		if names[i] == "" {
			names[i] = filepath.Base(o.Replay)
		}
	}
	em.send(Event{Type: "started", File: out.current, Ifaces: names})
	return pump(ctx, o, out, pkts, em, nil)
}

// rotator writes pcapng, optionally rotating files like dumpcap -b.
type rotator struct {
	o       Options
	ifaces  []pcapio.Interface
	f       *os.File
	w       *pcapio.NgWriter
	current string
	opened  time.Time
	size    uint64
	n       int
	files   []string
}

func newRotator(o Options, ifaces []pcapio.Interface) (*rotator, error) {
	r := &rotator{o: o, ifaces: ifaces}
	return r, r.open()
}

func (r *rotator) name() string {
	if r.o.RingSize == 0 && r.o.RingTime == 0 {
		return r.o.Output
	}
	ext := filepath.Ext(r.o.Output)
	base := strings.TrimSuffix(r.o.Output, ext)
	if ext == "" {
		ext = ".pcapng"
	}
	return fmt.Sprintf("%s_%05d_%s%s", base, r.n, time.Now().Format("20060102150405"), ext)
}

func (r *rotator) open() error {
	r.n++
	var w io.Writer
	if r.o.Output == "-" {
		w = os.Stdout
		r.current = "-"
	} else {
		r.current = r.name()
		f, err := os.OpenFile(r.current, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		r.f = f
		w = f
		r.files = append(r.files, r.current)
		if r.o.RingFiles > 0 && len(r.files) > r.o.RingFiles {
			os.Remove(r.files[0])
			r.files = r.files[1:]
		}
	}
	ng, err := pcapio.NewNgWriter(w, pcapio.SectionInfo{OS: runtime.GOOS + "/" + runtime.GOARCH, Application: "lazysniffer"})
	if err != nil {
		return err
	}
	for _, i := range r.ifaces {
		if _, err := ng.AddInterface(i); err != nil {
			return err
		}
	}
	r.w = ng
	r.opened = time.Now()
	r.size = 0
	return r.flush()
}

func (r *rotator) write(p packet) error {
	r.size += uint64(len(p.data)) + 32
	return r.w.WritePacket(pcapio.Record{Iface: p.iface, TS: p.ts, OrigLen: p.orig}, p.data)
}

func (r *rotator) flush() error { return r.w.Flush() }

func (r *rotator) rotate() error {
	if err := r.flush(); err != nil {
		return err
	}
	if r.f != nil {
		r.f.Close()
	}
	return r.open()
}

func (r *rotator) close() {
	r.flush()
	if r.f != nil {
		r.f.Close()
	}
}
