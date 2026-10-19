package ui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/poseydon/lazysniffer/internal/capture"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/proc"
	"github.com/poseydon/lazysniffer/internal/store"
)

type liveEventMsg struct {
	live *capture.Live
	ev   capture.Event
	ok   bool
}

type liveTickMsg struct{ live *capture.Live }

type ifaceTickMsg struct{}

// captureState is the live-capture part of the app.
type captureState struct {
	live        *capture.Live
	stats       capture.Event
	tempFile    string // capture file to offer saving or delete
	unsaved     bool
	ifaces      []capture.Iface
	ifaceErr    error
	sel         int
	checked     map[string]bool
	spark       map[string][]float64
	last        map[string]capture.Counters
	lastAt      time.Time
	startFocus  int // 0 interfaces, 1 recent files
	opts        capture.Options
	lastErr     string
	pktapActive bool
	canCapture  bool
	permFix     string
	procs       *proc.Table
}

func (m *App) initCapture() {
	c := &m.capt
	c.checked = map[string]bool{}
	c.spark = map[string][]float64{}
	c.opts = capture.Options{SnapLen: 262144, BufferMB: 4, PKTAP: capture.PKTAPSupported, Filter: m.cfg.CaptureFilter}
	m.refreshIfaces()
}

func (m *App) refreshIfaces() {
	c := &m.capt
	c.ifaces, c.ifaceErr = capture.Interfaces()
	c.canCapture, c.permFix = capture.CanCapture()
	if c.sel >= len(c.ifaces) {
		c.sel = 0
	}
}

// Tick periods (tests shorten or disable them).
var (
	ifaceTickEvery = time.Second
	liveTickEvery  = 250 * time.Millisecond
)

func (m *App) ifaceTick() tea.Cmd {
	if ifaceTickEvery == 0 {
		return nil
	}
	return tea.Tick(ifaceTickEvery, func(time.Time) tea.Msg { return ifaceTickMsg{} })
}

// onIfaceTick samples interface counters for the start screen sparklines.
func (m *App) onIfaceTick() tea.Cmd {
	if m.cap != nil {
		return m.ifaceTick()
	}
	c := &m.capt
	now := time.Now()
	cur := capture.ReadCounters()
	if c.last != nil {
		secs := now.Sub(c.lastAt).Seconds()
		for name, v := range cur {
			prev, ok := c.last[name]
			if !ok || secs <= 0 {
				continue
			}
			rate := float64(v.Packets-prev.Packets) / secs
			if v.Packets < prev.Packets {
				rate = 0
			}
			s := append(c.spark[name], rate)
			if len(s) > 30 {
				s = s[len(s)-30:]
			}
			c.spark[name] = s
		}
	}
	c.last, c.lastAt = cur, now
	return m.ifaceTick()
}

var sparkChars = []rune("▁▂▃▄▅▆▇█")

func sparkline(vals []float64, width int) string {
	if width <= 0 {
		return ""
	}
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	maxV := 0.0
	for _, v := range vals {
		maxV = max(maxV, v)
	}
	var b strings.Builder
	for i := len(vals); i < width; i++ {
		b.WriteRune(' ')
	}
	for _, v := range vals {
		idx := 0
		if maxV > 0 && v > 0 {
			idx = int(v / maxV * float64(len(sparkChars)-1))
			idx = max(idx, 1)
		}
		b.WriteRune(sparkChars[idx])
	}
	return b.String()
}

func rateLabel(r float64) string {
	switch {
	case r >= 1e6:
		return fmt.Sprintf("%.1fM/s", r/1e6)
	case r >= 1e3:
		return fmt.Sprintf("%.1fk/s", r/1e3)
	}
	return fmt.Sprintf("%.0f/s", r)
}

func (m *App) renderInterfaces(width int, focused bool) []string {
	th := m.theme
	c := &m.capt
	txt := lipgloss.NewStyle().Foreground(th.Text)
	mut := lipgloss.NewStyle().Foreground(th.Muted)
	var lines []string
	title := "Capture"
	if focused {
		title = "▸ Capture"
	}
	lines = append(lines, txt.Bold(true).Render(title))
	if c.ifaceErr != nil {
		return append(lines, lipgloss.NewStyle().Foreground(th.Err).Render("  "+c.ifaceErr.Error()))
	}
	if len(c.ifaces) == 0 {
		return append(lines, mut.Render("  No interfaces found"))
	}
	nameW, addrW := 10, 15
	for _, i := range c.ifaces {
		nameW = max(nameW, len(i.Label()))
	}
	nameW = min(nameW, 28)
	sparkW := max(min(width-nameW-addrW-22, 24), 6)
	for idx, i := range c.ifaces {
		if idx >= 14 {
			lines = append(lines, mut.Render(fmt.Sprintf("  … %d more (Capture › Options)", len(c.ifaces)-idx)))
			break
		}
		box := "  "
		if c.checked[i.Name] {
			box = "✓ "
		}
		addr := ""
		for _, a := range i.Addrs {
			if !strings.Contains(a, ":") {
				addr = a
				break
			}
		}
		if addr == "" && len(i.Addrs) > 0 {
			addr = i.Addrs[0]
		}
		vals := c.spark[i.Name]
		rate := 0.0
		if len(vals) > 0 {
			rate = vals[len(vals)-1]
		}
		row := box + fit(i.Label(), nameW) + "  " + fit(addr, addrW) + "  " + sparkline(vals, sparkW) + " " + fitRight(rateLabel(rate), 7)
		st := txt
		if !i.Up {
			st = mut
		}
		if idx == c.sel && focused {
			lines = append(lines, lipgloss.NewStyle().Background(th.SelBG).Foreground(th.SelFG).Render("▶ "+row))
		} else {
			lines = append(lines, st.Render("  "+row))
		}
	}
	lines = append(lines, "")
	fs := mut
	fstatus := ""
	if c.opts.Filter != "" {
		if _, err := capture.CheckFilter(1, c.opts.Filter); err != nil {
			fs = lipgloss.NewStyle().Foreground(th.Err)
			fstatus = " ✗ " + err.Error()
		} else {
			fs = lipgloss.NewStyle().Foreground(th.OK)
			fstatus = " ✓"
		}
	}
	filter := c.opts.Filter
	if filter == "" {
		filter = "none"
	}
	lines = append(lines, mut.Render("Capture filter: ")+fs.Render(filter+fstatus))
	if !c.canCapture {
		lines = append(lines, "", lipgloss.NewStyle().Foreground(th.Warn).Render("⚠ No capture permission: "+c.permFix))
	}
	return lines
}

func (m *App) ifaceKey(key string) (tea.Cmd, bool) {
	c := &m.capt
	n := min(len(c.ifaces), 14)
	switch key {
	case "up", "k":
		if n > 0 {
			c.sel = (c.sel - 1 + n) % n
		}
	case "down", "j":
		if n > 0 {
			c.sel = (c.sel + 1) % n
		}
	case "space":
		if c.sel < len(c.ifaces) {
			name := c.ifaces[c.sel].Name
			c.checked[name] = !c.checked[name]
			if !c.checked[name] {
				delete(c.checked, name)
			}
		}
	case "enter":
		return m.startCaptureSelected(), true
	case "f":
		return m.captureFilterDialog(), true
	default:
		return nil, false
	}
	return nil, true
}

func (m *App) selectedIfaces() []string {
	c := &m.capt
	var names []string
	for name := range c.checked {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 && c.sel < len(c.ifaces) {
		names = []string{c.ifaces[c.sel].Name}
	}
	return names
}

func (m *App) startCaptureSelected() tea.Cmd {
	ifs := m.selectedIfaces()
	if len(ifs) == 0 {
		return m.setFlash(true, "Select an interface first")
	}
	o := m.capt.opts
	o.Ifaces = ifs
	// PKTAP works per single interface capture on macOS.
	if len(ifs) > 1 {
		o.PKTAP = false
	}
	return m.startCapture(o)
}

func (m *App) startCapture(o capture.Options) tea.Cmd {
	if o.Filter != "" {
		if _, err := capture.CheckFilter(1, o.Filter); err != nil {
			return m.setFlash(true, "Invalid capture filter: %v", err)
		}
	}
	if m.capt.live != nil {
		return m.setFlash(true, "A capture is already running")
	}
	if m.cap != nil && m.capt.unsaved {
		return m.askSaveThen(func(m *App) tea.Cmd { return m.startCapture(o) })
	}
	l, err := capture.StartLive(o)
	if err != nil {
		return m.setFlash(true, "Cannot start capture: %v", err)
	}
	m.capt.live = l
	m.capt.stats = capture.Event{}
	m.capt.lastErr = ""
	m.capt.pktapActive = o.PKTAP
	if proc.Supported && o.Replay == "" {
		m.startProcSampler(l)
	}
	return m.listenLive(l)
}

func (m *App) listenLive(l *capture.Live) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-l.Events
		return liveEventMsg{live: l, ev: ev, ok: ok}
	}
}

func (m *App) onLiveEvent(msg liveEventMsg) tea.Cmd {
	c := &m.capt
	if msg.live != c.live || !msg.ok {
		return nil
	}
	ev := msg.ev
	next := m.listenLive(msg.live)
	switch ev.Type {
	case "started":
		path := msg.live.Path
		cmd := m.openLiveFile(path)
		if len(m.opts.Exec) > 0 && !m.execStarted {
			m.execStarted = true
			cmd = tea.Batch(cmd, m.runExec(msg.live))
		}
		c.tempFile = path
		c.unsaved = true
		if c.pktapActive && !m.cfg.ShowProcess {
			m.cfg.ShowProcess = true
			m.setupRows()
		}
		return tea.Batch(next, cmd, m.liveTick(msg.live))
	case "stats":
		c.stats = ev
	case "file":
		// Ring buffer switched files: follow the new one.
		return tea.Batch(next, m.openLiveFile(ev.File))
	case "error":
		c.lastErr = ev.Msg
		if ev.Perm {
			return tea.Batch(next, m.permissionDialog(ev.Msg))
		}
		return tea.Batch(next, m.setFlash(true, "Capture: %s", ev.Msg))
	case "stopped":
		c.stats = ev
	case "exited":
		c.live = nil
		if m.cap != nil {
			m.refreshLive()
			m.cap.Live = false
		}
		if c.lastErr != "" && m.cap == nil {
			return nil
		}
		return m.setFlash(false, "Capture stopped: %s packets", commas(m.capCount()))
	}
	return next
}

func (m *App) capCount() int {
	if m.cap == nil {
		return 0
	}
	return m.cap.Count()
}

func (m *App) permissionDialog(msg string) tea.Cmd {
	fix := m.capt.permFix
	lines := []string{
		"lazysniffer cannot open the capture device:",
		"  " + msg,
		"",
		"How to fix it:",
		"  • one-time setup (recommended): " + fix,
		"  • or capture remotely over SSH: Capture › Capture via SSH…",
		"  • or pipe from tcpdump: sudo tcpdump -U -w - | lazysniffer -i -",
		"",
		"Run `lazysniffer doctor` to check the result.",
	}
	return m.showText("Capture permission needed", lines)
}

// openLiveFile opens the growing capture file written by the helper.
func (m *App) openLiveFile(path string) tea.Cmd {
	keepFilter := m.filter
	cmd := m.openFileWith(path, true)
	if keepFilter != nil && !keepFilter.Empty() {
		m.filter = keepFilter
	}
	return cmd
}

func (m *App) liveTick(l *capture.Live) tea.Cmd {
	return tea.Tick(liveTickEvery, func(time.Time) tea.Msg { return liveTickMsg{live: l} })
}

func (m *App) onLiveTick(msg liveTickMsg) tea.Cmd {
	if msg.live != m.capt.live || m.cap == nil {
		return nil
	}
	if !m.loading {
		m.refreshLive()
	}
	return tea.Batch(m.liveTick(msg.live), m.checkKeylog())
}

// refreshLive indexes frames appended to the live file and extends the
// displayed list (filtering only the new frames).
func (m *App) refreshLive() {
	if m.cap == nil {
		return
	}
	if m.loading {
		m.refreshAfterLoad = true
		return
	}
	before := m.cap.Count()
	atEnd := len(m.displayed) == 0 || m.list.cursor >= len(m.displayed)-1
	n, err := m.cap.Refresh(context.Background())
	if err != nil {
		m.loadErr = err
	}
	if n == 0 {
		return
	}
	after := m.cap.Count()
	if m.filter == nil || m.filter.Empty() {
		m.extendDisplayed()
	} else {
		frames, err := engine.Filter(context.Background(), m.cap, m.filter, uint32(before+1), uint32(after), nil)
		if err == nil {
			m.displayed = append(m.displayed, frames...)
		}
	}
	if m.autoScroll && atEnd && len(m.displayed) > 0 && m.focus != paneDetails && m.focus != paneBytes {
		m.selectIndex(len(m.displayed) - 1)
	}
}

func (m *App) stopCapture() tea.Cmd {
	if m.capt.live == nil {
		return m.setFlash(true, "No capture is running")
	}
	m.capt.live.Stop()
	return m.setFlash(false, "Stopping capture…")
}

func (m *App) toggleCapture() tea.Cmd {
	if m.capt.live != nil {
		return m.stopCapture()
	}
	if m.cap == nil {
		return m.startCaptureSelected()
	}
	return m.captureOptionsDialog()
}

func (m *App) restartCapture() tea.Cmd {
	l := m.capt.live
	if l == nil {
		return m.setFlash(true, "No capture is running")
	}
	o := l.Opts
	o.Output = ""
	l.Stop()
	m.capt.live = nil
	m.capt.unsaved = false
	m.closeCurrent()
	return m.startCapture(o)
}

// askSaveThen offers to save the unsaved live capture before continuing.
func (m *App) askSaveThen(next func(m *App) tea.Cmd) tea.Cmd {
	items := []listItem{
		{label: "Save As…", run: func(m *App) tea.Cmd {
			cmd := m.saveAsDialog()
			return cmd
		}},
		{label: "Continue without saving", run: func(m *App) tea.Cmd {
			m.discardTemp()
			return next(m)
		}},
		{label: "Cancel", run: func(*App) tea.Cmd { return nil }},
	}
	d := newList("Unsaved packets", items)
	d.footer = fmt.Sprintf("The captured %s packets have not been saved.", commas(m.capCount()))
	return m.push(d)
}

func (m *App) discardTemp() {
	c := &m.capt
	if c.live != nil {
		c.live.Stop()
		c.live = nil
	}
	path := c.tempFile
	c.tempFile, c.unsaved = "", false
	m.closeCurrent()
	if path != "" {
		os.Remove(path)
	}
}

func (m *App) captureFilterDialog() tea.Cmd {
	d := newInput("Capture Filter", "BPF syntax, e.g. tcp port 443 or host 10.0.0.1 and not arp:", m.capt.opts.Filter, func(m *App, v string) tea.Cmd {
		m.capt.opts.Filter = strings.TrimSpace(v)
		m.cfg.CaptureFilter = m.capt.opts.Filter
		_ = m.cfg.Save()
		return nil
	})
	d.validate = func(v string) error { _, err := capture.CheckFilter(1, v); return err }
	d.help = []string{"Capture filters decide what is recorded; display filters (/) decide what is shown."}
	return m.push(d)
}

func (m *App) captureOptionsDialog() tea.Cmd {
	c := &m.capt
	o := &c.opts
	var items []listItem
	items = append(items, listItem{label: "▶ Start capture", detail: strings.Join(m.selectedIfaces(), ", "), run: (*App).startCaptureSelected})
	items = append(items, listItem{label: "Interfaces…", detail: fmt.Sprintf("%d selected", len(m.selectedIfaces())), keep: true, run: func(m *App) tea.Cmd {
		var its []listItem
		for _, i := range m.capt.ifaces {
			i := i
			on := m.capt.checked[i.Name]
			its = append(its, listItem{label: i.Label(), detail: strings.Join(i.Addrs, " "), checked: &on, keep: true, run: func(m *App) tea.Cmd {
				m.capt.checked[i.Name] = !m.capt.checked[i.Name]
				if !m.capt.checked[i.Name] {
					delete(m.capt.checked, i.Name)
				}
				on = m.capt.checked[i.Name]
				return nil
			}})
		}
		d := newList("Capture Interfaces", its)
		d.footer = "enter toggles · esc done"
		return m.push(d)
	}})
	items = append(items, listItem{label: "Capture filter…", detail: orNone(o.Filter), keep: true, run: func(m *App) tea.Cmd {
		m.pop()
		return tea.Sequence(m.captureFilterDialog(), func() tea.Msg { return nil })
	}})
	promisc := !o.NoPromisc
	items = append(items, listItem{label: "Promiscuous mode", checked: &promisc, keep: true, run: func(m *App) tea.Cmd {
		o.NoPromisc = !o.NoPromisc
		promisc = !o.NoPromisc
		return nil
	}})
	if capture.PKTAPSupported {
		items = append(items, listItem{label: "Process information (PKTAP)", checked: &o.PKTAP, keep: true, run: func(m *App) tea.Cmd {
			o.PKTAP = !o.PKTAP
			return nil
		}})
	}
	items = append(items, listItem{label: "Monitor mode (Wi-Fi)", checked: &o.Monitor, keep: true, run: func(m *App) tea.Cmd {
		o.Monitor = !o.Monitor
		return nil
	}})
	items = append(items, listItem{label: "Snapshot length…", detail: fmt.Sprintf("%d bytes", o.SnapLen), run: func(m *App) tea.Cmd {
		return m.numberDialog("Snapshot length (bytes)", o.SnapLen, func(v int) { o.SnapLen = v })
	}})
	items = append(items, listItem{label: "Buffer size…", detail: fmt.Sprintf("%d MB", o.BufferMB), run: func(m *App) tea.Cmd {
		return m.numberDialog("Kernel buffer size (MB)", o.BufferMB, func(v int) { o.BufferMB = v })
	}})
	items = append(items, listItem{label: "Stop after seconds…", detail: durLabel(o.StopAfter), run: func(m *App) tea.Cmd {
		return m.numberDialog("Stop after N seconds (0 = never)", int(o.StopAfter.Seconds()), func(v int) { o.StopAfter = time.Duration(v) * time.Second })
	}})
	items = append(items, listItem{label: "Stop after packets…", detail: zeroNever(int(o.StopPackets)), run: func(m *App) tea.Cmd {
		return m.numberDialog("Stop after N packets (0 = never)", int(o.StopPackets), func(v int) { o.StopPackets = uint64(v) })
	}})
	d := newList("Capture Options", items)
	d.footer = "space/enter toggles · esc closes"
	return m.push(d)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func durLabel(d time.Duration) string {
	if d == 0 {
		return "never"
	}
	return d.String()
}

func zeroNever(n int) string {
	if n == 0 {
		return "never"
	}
	return commas(n)
}

func (m *App) numberDialog(title string, cur int, set func(int)) tea.Cmd {
	d := newInput(title, "", strconv.Itoa(cur), func(m *App, v string) tea.Cmd {
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		set(n)
		return nil
	})
	d.validate = func(v string) error {
		if _, err := strconv.Atoi(strings.TrimSpace(v)); err != nil {
			return fmt.Errorf("enter a whole number")
		}
		return nil
	}
	return m.push(d)
}

func (m *App) sshDialog() tea.Cmd {
	d := newInput("Capture via SSH", "Host (user@host or ~/.ssh/config alias), optionally :interface", m.cfg.LastSSH, func(m *App, v string) tea.Cmd {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil
		}
		m.cfg.LastSSH = v
		_ = m.cfg.Save()
		host, iface, _ := strings.Cut(v, ":")
		return m.startSSH(capture.SSHOptions{Host: host, Iface: iface, Filter: m.capt.opts.Filter})
	})
	d.help = []string{
		"Runs: ssh host 'sudo -n tcpdump -U -s 0 -w - -i IFACE \"not port 22\"'",
		"The remote user needs passwordless sudo for tcpdump (or capture rights).",
		"Uses your ssh keys/agent and ~/.ssh/config.",
	}
	return m.push(d)
}

func (m *App) startSSH(o capture.SSHOptions) tea.Cmd {
	if m.capt.live != nil {
		return m.setFlash(true, "A capture is already running")
	}
	l, err := capture.StartSSH(o)
	if err != nil {
		return m.setFlash(true, "ssh: %v", err)
	}
	m.capt.live = l
	m.capt.pktapActive = false
	return tea.Batch(m.listenLive(l), m.setFlash(false, "Connecting to %s…", o.Host))
}

// startStdin captures a pcap stream piped into lazysniffer.
func (m *App) startStdin() tea.Cmd {
	l, err := capture.StartPipe(os.Stdin, "stdin", nil)
	if err != nil {
		return m.setFlash(true, "stdin: %v", err)
	}
	m.capt.live = l
	return m.listenLive(l)
}

func (m *App) replayDialog() tea.Cmd {
	d := newInput("Replay File as Live Capture", "Capture file to replay in real time:", "", func(m *App, v string) tea.Cmd {
		path := expandHome(strings.TrimSpace(v))
		if _, err := os.Stat(path); err != nil {
			return m.setFlash(true, "%v", err)
		}
		return m.startCapture(capture.Options{Replay: path, ReplaySpeed: 1})
	})
	d.complete = completePath
	d.help = []string{"Plays packets back with their original timing — handy for demos and training."}
	return m.push(d)
}

func (m *App) liveStatus() string {
	c := &m.capt
	if c.live == nil {
		return ""
	}
	el := time.Since(c.live.Start).Round(time.Second)
	s := fmt.Sprintf("● REC %s %s", c.live.Desc, fmtClock(el))
	if c.stats.Dropped > 0 {
		s += fmt.Sprintf(" · dropped %s", commas(int(c.stats.Dropped)))
	}
	return s
}

func fmtClock(d time.Duration) string {
	h := int(d.Hours())
	mm := int(d.Minutes()) % 60
	ss := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, mm, ss)
}

var _ = store.FlagMarked

type execDoneMsg struct {
	live *capture.Live
	err  error
}

// runExec starts the command given to `lazysniffer run`, with SSLKEYLOGFILE
// pointing at the key log lazysniffer reads.
func (m *App) runExec(l *capture.Live) tea.Cmd {
	args := m.opts.Exec
	keys := m.opts.KeylogFile
	return func() tea.Msg {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = append(os.Environ(), "SSLKEYLOGFILE="+keys)
		cmd.Stdout, cmd.Stderr = nil, nil
		err := cmd.Run()
		time.Sleep(1500 * time.Millisecond) // let the last packets arrive
		return execDoneMsg{live: l, err: err}
	}
}

func (m *App) onExecDone(msg execDoneMsg) tea.Cmd {
	if msg.live != m.capt.live {
		return nil
	}
	text := "command finished"
	if msg.err != nil {
		text = fmt.Sprintf("command finished: %v", msg.err)
	}
	if m.opts.KeepOpen {
		return m.setFlash(msg.err != nil, "%s; capture still running (c to stop)", text)
	}
	m.capt.live.Stop()
	return m.setFlash(msg.err != nil, "%s; stopping capture", text)
}

// extcapDialog lists the extcap interfaces (sshdump, androiddump, udpdump,
// randpktdump, …) and starts a capture on the chosen one.
func (m *App) extcapDialog() tea.Cmd {
	ifaces := capture.ExtcapInterfaces()
	if len(ifaces) == 0 {
		return m.setFlash(true, "No extcap tools found (they ship with Wireshark: set $WIRESHARK_EXTCAP_DIR or install Wireshark)")
	}
	var items []listItem
	for _, ifc := range ifaces {
		ifc := ifc
		items = append(items, listItem{label: ifc.Name, detail: ifc.Display, run: func(m *App) tea.Cmd {
			args, err := capture.ExtcapArgs(ifc)
			if err != nil {
				return m.setFlash(true, "%s: %v", ifc.Name, err)
			}
			vals := map[string]string{}
			for _, a := range args {
				vals[a.Call] = a.Default
			}
			return m.extcapForm(ifc, args, vals)
		}})
	}
	return m.push(newList("Capture via extcap", items))
}

// extcapForm shows the options of an extcap interface; enter edits one.
func (m *App) extcapForm(ifc capture.ExtcapIface, args []capture.ExtcapArg, vals map[string]string) tea.Cmd {
	var items []listItem
	items = append(items, listItem{label: "▶ Start capture", run: func(m *App) tea.Cmd {
		for _, a := range args {
			if a.Required && vals[a.Call] == "" {
				return m.setFlash(true, "%s is required", a.Display)
			}
		}
		if m.capt.live != nil {
			return m.setFlash(true, "A capture is already running")
		}
		l, err := capture.StartExtcap(capture.ExtcapOptions{Iface: ifc, Args: vals, Filter: m.capt.opts.Filter})
		if err != nil {
			return m.setFlash(true, "%v", err)
		}
		m.capt.live = l
		m.capt.pktapActive = false
		return tea.Batch(m.listenLive(l), m.setFlash(false, "Starting %s…", ifc.Name))
	}})
	for _, a := range args {
		a := a
		label := a.Display
		if label == "" {
			label = a.Call
		}
		val := vals[a.Call]
		if a.Type == "password" && val != "" {
			val = strings.Repeat("•", len(val))
		}
		items = append(items, listItem{label: label, detail: a.Call + " = " + val, run: func(m *App) tea.Cmd {
			edit := func(v string) tea.Cmd {
				vals[a.Call] = v
				m.pop() // the old form
				return m.extcapForm(ifc, args, vals)
			}
			switch {
			case a.Type == "boolflag" || a.Type == "boolean":
				if vals[a.Call] == "true" {
					return edit("false")
				}
				return edit("true")
			case a.Type == "selector" && len(a.Values) > 0:
				var vi []listItem
				for _, v := range a.Values {
					v := v
					vi = append(vi, listItem{label: v.Display, detail: v.Value, run: func(m *App) tea.Cmd { m.pop(); return edit(v.Value) }})
				}
				return m.push(newList(label, vi))
			}
			d := newInput(label, a.Tooltip, vals[a.Call], func(m *App, v string) tea.Cmd { return edit(strings.TrimSpace(v)) })
			return m.push(d)
		}})
	}
	return m.push(newList("extcap: "+ifc.Name, items))
}
