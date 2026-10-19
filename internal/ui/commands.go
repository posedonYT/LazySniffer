package ui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/poseydon/lazysniffer/internal/columns"
	"github.com/poseydon/lazysniffer/internal/config"
	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/export"
	"github.com/poseydon/lazysniffer/internal/store"
	"github.com/poseydon/lazysniffer/internal/version"
)

// ---- File ----

func (m *App) openFileDialog() tea.Cmd {
	start := ""
	if m.cap != nil {
		start = filepath.Dir(m.cap.Path) + "/"
	} else if wd, err := os.Getwd(); err == nil {
		start = wd + "/"
	}
	d := newInput("Open Capture File", "Path (tab completes):", start, func(m *App, v string) tea.Cmd {
		return m.openFile(expandHome(strings.TrimSpace(v)))
	})
	d.complete = completePath
	d.help = []string{"pcap, pcapng and their gzip/zstd/lz4 compressed forms"}
	return m.push(d)
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}

// completePath completes a file path to the longest common prefix.
func completePath(v string) string {
	p := expandHome(v)
	dir, base := filepath.Split(p)
	if dir == "" {
		dir = "."
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return v
	}
	var matches []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), base) && (!strings.HasPrefix(e.Name(), ".") || strings.HasPrefix(base, ".")) {
			name := e.Name()
			if e.IsDir() {
				name += "/"
			}
			matches = append(matches, name)
		}
	}
	if len(matches) == 0 {
		return v
	}
	common := matches[0]
	for _, mm := range matches[1:] {
		for !strings.HasPrefix(mm, common) {
			common = common[:len(common)-1]
		}
	}
	d, _ := filepath.Split(v)
	return d + common
}

func (m *App) recentDialog() tea.Cmd {
	if len(m.cfg.RecentFiles) == 0 {
		return m.setFlash(true, "No recent files")
	}
	var items []listItem
	for _, p := range m.cfg.RecentFiles {
		p := p
		detail := ""
		if st, err := os.Stat(p); err == nil {
			detail = humanBytes(st.Size())
		} else {
			detail = "missing"
		}
		items = append(items, listItem{label: p, detail: detail, run: func(m *App) tea.Cmd { return m.openFile(p) }})
	}
	return m.push(newList("Open Recent", items))
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f kB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}

func (m *App) closeCapture() tea.Cmd {
	if m.capt.unsaved {
		return m.askSaveThen(func(m *App) tea.Cmd { return nil })
	}
	if m.cap != nil && m.cap.Unsaved() {
		return m.confirm("Unsaved changes", "Packet comments were changed. Close without saving?", func(m *App) tea.Cmd {
			m.closeCurrent()
			return nil
		})
	}
	m.closeCurrent()
	return nil
}

func (m *App) reload() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	path := m.cap.Path
	sel := m.selected
	cmd := m.openFile(path)
	m.selected = 0
	_ = sel
	return cmd
}

func (m *App) quit() tea.Cmd {
	if m.capt.unsaved {
		return m.askSaveThen(func(m *App) tea.Cmd { m.closeCurrent(); return tea.Quit })
	}
	if m.cap != nil && m.cap.Unsaved() {
		return m.confirm("Unsaved changes", "Packet comments were changed. Quit without saving?", func(m *App) tea.Cmd {
			m.closeCurrent()
			return tea.Quit
		})
	}
	m.closeCurrent()
	return tea.Quit
}

func (m *App) saveAsDialog() tea.Cmd {
	all := make([]uint32, m.cap.Count())
	for i := range all {
		all[i] = uint32(i + 1)
	}
	return m.saveFramesDialog("Save Capture As", all)
}

func (m *App) saveFramesDialog(title string, frames []uint32) tea.Cmd {
	def := strings.TrimSuffix(m.cap.Path, filepath.Ext(m.cap.Path)) + "-saved.pcapng"
	d := newInput(title, fmt.Sprintf("%s packets → file (.pcapng or .pcap):", commas(len(frames))), def, func(m *App, v string) tea.Cmd {
		path := expandHome(strings.TrimSpace(v))
		if err := export.SavePackets(m.cap, frames, path, export.FormatFromPath(path)); err != nil {
			return m.setFlash(true, "Save failed: %v", err)
		}
		if m.capt.unsaved && len(frames) == m.cap.Count() && m.capt.live == nil {
			// The temporary capture is now safely stored.
			os.Remove(m.capt.tempFile)
			m.capt.unsaved, m.capt.tempFile = false, ""
			m.cfg.AddRecent(path)
			_ = m.cfg.Save()
		}
		return m.setFlash(false, "Saved %s packets to %s", commas(len(frames)), path)
	})
	d.complete = completePath
	return m.push(d)
}

func (m *App) exportDialog() tea.Cmd {
	marked := m.cap.FramesWithFlag(store.FlagMarked)
	ignored := m.cap.FramesWithFlag(store.FlagIgnored)
	isIgnored := map[uint32]bool{}
	for _, n := range ignored {
		isIgnored[n] = true
	}
	notIgnored := func(in []uint32) []uint32 {
		var out []uint32
		for _, n := range in {
			if !isIgnored[n] {
				out = append(out, n)
			}
		}
		return out
	}
	all := make([]uint32, m.cap.Count())
	for i := range all {
		all[i] = uint32(i + 1)
	}
	displayed := append([]uint32(nil), m.displayed...)
	items := []listItem{
		{label: "All packets", detail: commas(len(all)), run: func(m *App) tea.Cmd { return m.saveFramesDialog("Export All Packets", notIgnored(all)) }},
		{label: "Displayed packets", detail: commas(len(displayed)), run: func(m *App) tea.Cmd {
			return m.saveFramesDialog("Export Displayed Packets", notIgnored(displayed))
		}},
		{label: "Marked packets", detail: commas(len(marked)), disabled: len(marked) == 0, run: func(m *App) tea.Cmd {
			return m.saveFramesDialog("Export Marked Packets", notIgnored(marked))
		}},
		{label: "Selected packet only", detail: fmt.Sprint(m.selected), disabled: m.selected == 0, run: func(m *App) tea.Cmd {
			return m.saveFramesDialog("Export Selected Packet", []uint32{m.selected})
		}},
		{label: "Range…", detail: "e.g. 1-100,200", run: func(m *App) tea.Cmd {
			d := newInput("Export Packet Range", "Frame numbers (1-10,15,20-):", "", func(m *App, v string) tea.Cmd {
				r, err := parseFrameRange(v, m.cap.Count())
				if err != nil {
					return m.setFlash(true, "%v", err)
				}
				return m.saveFramesDialog("Export Packet Range", notIgnored(r))
			})
			d.validate = func(v string) error { _, err := parseFrameRange(v, m.cap.Count()); return err }
			return m.push(d)
		}},
	}
	d := newList("Export Specified Packets", items)
	if len(ignored) > 0 {
		d.footer = fmt.Sprintf("%d ignored packets are excluded", len(ignored))
	}
	return m.push(d)
}

// parseFrameRange parses "1-10,15,20-" into frame numbers.
func parseFrameRange(s string, total int) ([]uint32, error) {
	var out []uint32
	seen := map[uint32]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, b, isRange := strings.Cut(part, "-")
		lo, err := strconv.Atoi(strings.TrimSpace(a))
		if err != nil || lo < 1 {
			return nil, fmt.Errorf("%q is not a valid frame number", a)
		}
		hi := lo
		if isRange {
			if strings.TrimSpace(b) == "" {
				hi = total
			} else if hi, err = strconv.Atoi(strings.TrimSpace(b)); err != nil || hi < lo {
				return nil, fmt.Errorf("%q is not a valid range", part)
			}
		}
		for n := lo; n <= hi && n <= total; n++ {
			if !seen[uint32(n)] {
				seen[uint32(n)] = true
				out = append(out, uint32(n))
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the range selects no packets")
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (m *App) propertiesDialog() tea.Cmd {
	c := m.cap
	f := c.File()
	var lines []string
	add := func(k, v string) { lines = append(lines, fmt.Sprintf("%-22s %s", k+":", v)) }
	lines = append(lines, "File")
	add("  Name", c.Path)
	if st, err := os.Stat(c.Path); err == nil {
		add("  Length", humanBytes(st.Size()))
	}
	add("  Format", f.Format.String())
	if len(f.Section.Comments) > 0 {
		add("  Comments", strings.Join(f.Section.Comments, " / "))
	}
	if f.Section.Application != "" {
		add("  Application", f.Section.Application)
	}
	if f.Section.OS != "" {
		add("  OS", f.Section.OS)
	}
	if f.Section.Hardware != "" {
		add("  Hardware", f.Section.Hardware)
	}
	n := c.Count()
	lines = append(lines, "", "Time")
	if n > 0 {
		first, last := c.Frame(1).TS, c.Frame(uint32(n)).TS
		add("  First packet", dissect.FormatAbsTime(first, false))
		add("  Last packet", dissect.FormatAbsTime(last, false))
		add("  Elapsed", dissect.FormatRelTime(last-first)+" s")
	}
	lines = append(lines, "", "Interfaces")
	for i, ifc := range f.Interfaces {
		name := ifc.Name
		if name == "" {
			name = "unknown"
		}
		add(fmt.Sprintf("  #%d %s", i, name), fmt.Sprintf("%s, snaplen %d%s", ifc.LinkType, ifc.SnapLen, strings.TrimSpace(" "+ifc.Description)))
		if ifc.Filter != "" {
			add("     capture filter", ifc.Filter)
		}
	}
	var bytes int64
	for i := 1; i <= n; i++ {
		bytes += int64(c.Frame(uint32(i)).Len)
	}
	lines = append(lines, "", "Statistics")
	add("  Packets", commas(n))
	add("  Displayed", commas(len(m.displayed)))
	add("  Marked", commas(len(c.FramesWithFlag(store.FlagMarked))))
	add("  Bytes", commas(int(bytes)))
	if n > 1 {
		secs := float64(c.Frame(uint32(n)).TS-c.Frame(1).TS) / 1e9
		if secs > 0 {
			add("  Average pps", fmt.Sprintf("%.1f", float64(n)/secs))
			add("  Average packet size", fmt.Sprintf("%d B", bytes/int64(n)))
			add("  Average bit rate", fmt.Sprintf("%s/s", humanBits(float64(bytes)*8/secs)))
		}
	}
	if m.filter != nil && !m.filter.Empty() {
		add("  Display filter", m.filter.Text)
	}
	if len(f.Secrets) > 0 {
		add("  Decryption secrets", fmt.Sprintf("%d block(s)", len(f.Secrets)))
	}
	return m.showText("Capture File Properties", lines)
}

func humanBits(b float64) string {
	switch {
	case b >= 1e9:
		return fmt.Sprintf("%.2f Gbit", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.2f Mbit", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.1f kbit", b/1e3)
	}
	return fmt.Sprintf("%.0f bit", b)
}

// ---- Edit ----

func (m *App) toggleMark() tea.Cmd {
	if m.selected == 0 {
		return nil
	}
	m.cap.ToggleFlag(m.selected, store.FlagMarked)
	m.dissectSelected()
	cmd, _ := m.listKey("down")
	return cmd
}

func (m *App) markAllDisplayed() tea.Cmd {
	for _, n := range m.displayed {
		m.cap.SetFlag(n, store.FlagMarked, true)
	}
	return m.setFlash(false, "Marked %s packets", commas(len(m.displayed)))
}

func (m *App) unmarkAll() tea.Cmd {
	m.cap.ClearFlag(store.FlagMarked)
	return m.setFlash(false, "All marks cleared")
}

func (m *App) gotoFlagged(dir int) tea.Cmd {
	n := len(m.displayed)
	for i := 1; i <= n; i++ {
		idx := m.list.cursor + dir*i
		if idx < 0 || idx >= n {
			break
		}
		if m.cap.Frame(m.displayed[idx]).Flags&store.FlagMarked != 0 {
			m.selectIndex(idx)
			return nil
		}
	}
	return m.setFlash(true, "No more marked packets")
}

func (m *App) toggleIgnore() tea.Cmd {
	if m.selected == 0 {
		return nil
	}
	m.cap.ToggleFlag(m.selected, store.FlagIgnored)
	delete(m.rowCache, m.selected)
	m.selPI = nil
	m.dissectSelected()
	return nil
}

func (m *App) unignoreAll() tea.Cmd {
	m.cap.ClearFlag(store.FlagIgnored)
	m.rowCache = nil
	m.dissectSelected()
	return nil
}

func (m *App) toggleTimeRef() tea.Cmd {
	if m.selected == 0 {
		return nil
	}
	m.cap.ToggleFlag(m.selected, store.FlagTimeRef)
	m.rowCache = nil
	m.selPI = nil
	m.dissectSelected()
	return nil
}

func (m *App) clearTimeRefs() tea.Cmd {
	m.cap.ClearFlag(store.FlagTimeRef)
	m.rowCache = nil
	m.dissectSelected()
	return nil
}

func (m *App) commentDialog() tea.Cmd {
	if m.selected == 0 {
		return nil
	}
	num := m.selected
	cur := strings.Join(m.cap.Comments(num), " / ")
	d := newInput(fmt.Sprintf("Comment for Packet %d", num), "Comment (empty removes it):", cur, func(m *App, v string) tea.Cmd {
		v = strings.TrimSpace(v)
		if v == "" {
			m.cap.SetComments(num, nil)
		} else {
			m.cap.SetComments(num, []string{v})
		}
		delete(m.rowCache, num)
		m.selPI = nil
		m.dissectSelected()
		return m.setFlash(false, "Comment saved in memory — use File › Save As to keep it")
	})
	d.help = []string{"Comments are stored in pcapng files and can be filtered with frame.comment"}
	return m.push(d)
}

func (m *App) prefsDialog() tea.Cmd {
	cfg := m.cfg
	toggle := func(label string, p *bool, after func(m *App)) listItem {
		return listItem{label: label, checked: p, keep: true, run: func(m *App) tea.Cmd {
			*p = !*p
			if after != nil {
				after(m)
			}
			_ = m.cfg.Save()
			return nil
		}}
	}
	refresh := func(m *App) {
		m.applyResolution()
		m.setupRows()
		m.selPI = nil
		m.dissectSelected()
	}
	items := []listItem{
		{label: "Theme", detail: cfg.Theme, keep: true, run: func(m *App) tea.Cmd {
			switch m.cfg.Theme {
			case "auto", "":
				m.cfg.Theme = "dark"
			case "dark":
				m.cfg.Theme = "light"
			default:
				m.cfg.Theme = "auto"
			}
			m.applyThemeSetting()
			m.pop()
			_ = m.cfg.Save()
			return m.prefsDialog()
		}},
		toggle("Mouse support", &cfg.Mouse, nil),
		toggle("Colorize packet list", &cfg.ColorRows, func(m *App) { m.colorize = m.cfg.ColorRows }),
		toggle("Resolve MAC addresses (vendor names)", &cfg.ResolveMAC, refresh),
		toggle("Resolve network addresses (reverse DNS)", &cfg.ResolveNetwork, func(m *App) { refresh(m) }),
		toggle("Resolve transport ports (service names)", &cfg.ResolvePorts, refresh),
		toggle("Show Process column", &cfg.ShowProcess, refresh),
		{label: "Time precision", detail: fmt.Sprintf("%d digits", cfg.TimePrecision), keep: true, run: func(m *App) tea.Cmd {
			m.cfg.TimePrecision = map[int]int{0: 3, 3: 6, 6: 9, 9: 0}[m.cfg.TimePrecision]
			m.setupRows()
			_ = m.cfg.Save()
			m.pop()
			return m.prefsDialog()
		}},
		{label: "Edit coloring rules file…", detail: "colorfilters", run: (*App).editColorRules},
	}
	d := newList("Preferences", items)
	d.footer = "Saved to " + m.cfg.Path()
	return m.push(d)
}

func (m *App) applyThemeSetting() {
	switch m.cfg.Theme {
	case "dark":
		m.theme = NewTheme(true)
	case "light":
		m.theme = NewTheme(false)
	}
	m.rowCache = nil
}

func (m *App) toggleTheme() tea.Cmd {
	m.theme = NewTheme(!m.theme.Dark)
	if m.theme.Dark {
		m.cfg.Theme = "dark"
	} else {
		m.cfg.Theme = "light"
	}
	_ = m.cfg.Save()
	return nil
}

// editColorRules opens the colorfilters file in $EDITOR and reloads it.
func (m *App) editColorRules() tea.Cmd {
	path := filepath.Join(config.Dir(), "colorfilters")
	if _, err := os.Stat(path); err != nil {
		os.MkdirAll(config.Dir(), 0o755)
		if err := os.WriteFile(path, []byte(config.DefaultColorRules), 0o644); err != nil {
			return m.setFlash(true, "%v", err)
		}
	}
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	parts := strings.Fields(editor)
	c := exec.Command(parts[0], append(parts[1:], path)...)
	return tea.ExecProcess(c, func(err error) tea.Msg {
		return colorRulesEditedMsg{err}
	})
}

type colorRulesEditedMsg struct{ err error }

// ---- View ----

func (m *App) timeFormatMenu() tea.Cmd {
	var items []listItem
	cur := m.rows.Time
	for _, tf := range columns.TimeFormats {
		tf := tf
		label := tf.Title
		if tf.F == cur {
			label = "● " + label
		} else {
			label = "  " + label
		}
		items = append(items, listItem{label: label, run: func(m *App) tea.Cmd {
			m.cfg.TimeFormat = timeFormatName(tf.F)
			_ = m.cfg.Save()
			m.rows.Time = tf.F
			m.rowCache = nil
			m.list.widths = nil
			return nil
		}})
	}
	return m.push(newList("Time Display Format", items))
}

func (m *App) resolutionMenu() tea.Cmd {
	m.pop()
	return m.prefsDialog()
}

func (m *App) toggleColorize() tea.Cmd {
	m.colorize = !m.colorize
	m.cfg.ColorRows = m.colorize
	_ = m.cfg.Save()
	return nil
}

func (m *App) toggleColorStyle() tea.Cmd {
	if m.cfg.ColorStyle == "foreground" {
		m.cfg.ColorStyle = "background"
	} else {
		m.cfg.ColorStyle = "foreground"
	}
	_ = m.cfg.Save()
	return nil
}

func (m *App) toggleProcessColumn() tea.Cmd {
	m.cfg.ShowProcess = !m.cfg.ShowProcess
	_ = m.cfg.Save()
	m.setupRows()
	m.list.widths = nil
	return nil
}

func (m *App) toggleZoom() tea.Cmd {
	m.zoom = !m.zoom
	return nil
}

func (m *App) packetTab() tea.Cmd {
	if m.selPI == nil {
		return nil
	}
	var b strings.Builder
	export.WriteTree(&b, &m.selPI.Tree.Root)
	b.WriteString("\n")
	export.WriteHex(&b, m.selPI.Sources[0].Data)
	return m.showText(fmt.Sprintf("Packet %d", m.selected), strings.Split(strings.TrimRight(b.String(), "\n"), "\n"))
}

func (m *App) toggleAutoScroll() tea.Cmd {
	m.autoScroll = !m.autoScroll
	return m.setFlash(false, "Auto scroll %s", onOff(m.autoScroll))
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// ---- Go ----

func (m *App) gotoDialog() tea.Cmd {
	d := newInput("Go to Packet", "Packet number:", "", func(m *App, v string) tea.Cmd {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 {
			return m.setFlash(true, "%q is not a packet number", v)
		}
		return m.gotoFrame(uint32(n))
	})
	d.validate = func(v string) error {
		if strings.TrimSpace(v) == "" {
			return nil
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 || n > m.cap.Count() {
			return fmt.Errorf("enter a number between 1 and %d", m.cap.Count())
		}
		return nil
	}
	return m.push(d)
}

// convStep moves to the next/previous displayed packet of the same conversation.
func (m *App) convStep(dir int) tea.Cmd {
	if m.selPI == nil {
		return nil
	}
	conv := m.selPI.Conv
	src, dst := m.selPI.NetSrc, m.selPI.NetDst
	w := m.cap.Session().NewWorker(dissect.Options{Want: make([]bool, dissect.NumFields())})
	for idx := m.list.cursor + dir; idx >= 0 && idx < len(m.displayed); idx += dir {
		pi := w.Dissect(m.cap.Input(m.displayed[idx]))
		if conv != nil && pi.Conv == conv ||
			conv == nil && !src.IsZero() && (pi.NetSrc == src && pi.NetDst == dst || pi.NetSrc == dst && pi.NetDst == src) {
			m.selectIndex(idx)
			return nil
		}
	}
	return m.setFlash(true, "No more packets in this conversation")
}

// ---- Analyze ----

func (m *App) savedFiltersDialog() tea.Cmd {
	var items []listItem
	for _, sf := range m.cfg.SavedFilters {
		sf := sf
		items = append(items, listItem{label: sf.Name, detail: sf.Filter, run: func(m *App) tea.Cmd { return m.applyFilter(sf.Filter) }})
	}
	if t := strings.TrimSpace(m.fbar.text()); t != "" {
		items = append(items, listItem{label: "★ Save current filter…", detail: t, run: func(m *App) tea.Cmd {
			return m.push(newInput("Save Display Filter", "Name:", "", func(m *App, name string) tea.Cmd {
				if name = strings.TrimSpace(name); name == "" {
					name = t
				}
				m.cfg.SavedFilters = append(m.cfg.SavedFilters, config.SavedFilter{Name: name, Filter: t})
				_ = m.cfg.Save()
				return m.setFlash(false, "Saved filter %q", name)
			}))
		}})
	}
	if len(m.cfg.FilterHistory) > 0 {
		items = append(items, listItem{label: "History…", detail: fmt.Sprintf("%d recent filters", len(m.cfg.FilterHistory)), run: func(m *App) tea.Cmd {
			var h []listItem
			for _, f := range m.cfg.FilterHistory {
				f := f
				h = append(h, listItem{label: f, run: func(m *App) tea.Cmd { return m.applyFilter(f) }})
			}
			return m.push(newList("Filter History", h))
		}})
	}
	d := newList("Display Filters", items)
	d.filter = true
	return m.push(d)
}

// selectedFieldExpr builds a filter expression for the selected tree item.
func (m *App) selectedFieldExpr() (string, error) {
	n := m.details.current()
	if n == nil || m.focus != paneDetails && n == nil {
		return "", fmt.Errorf("select a field in the Details pane first")
	}
	if n.Field == nil {
		return "", fmt.Errorf("the selected item is not a filterable field")
	}
	if n.Field.Type == dissect.FtProtocol || n.Field.Type == dissect.FtNone {
		return n.Field.Abbrev, nil
	}
	return n.Field.FilterExpr(n.Value), nil
}

func (m *App) filterFromFieldMenu(apply bool) tea.Cmd {
	expr, err := m.selectedFieldExpr()
	if err != nil {
		return m.setFlash(true, "%v", err)
	}
	cur := strings.TrimSpace(m.fbar.text())
	wrap := func(s string) string {
		if strings.ContainsAny(s, "|&") || strings.Contains(s, " or ") || strings.Contains(s, " and ") {
			return "(" + s + ")"
		}
		return s
	}
	type opt struct{ label, f string }
	opts := []opt{{"Selected", expr}, {"Not Selected", "!(" + expr + ")"}}
	if cur != "" {
		opts = append(opts,
			opt{"…and Selected", wrap(cur) + " && " + expr},
			opt{"…or Selected", wrap(cur) + " || " + expr},
			opt{"…and not Selected", wrap(cur) + " && !(" + expr + ")"},
			opt{"…or not Selected", wrap(cur) + " || !(" + expr + ")"})
	}
	title := "Apply as Filter"
	if !apply {
		title = "Prepare as Filter"
	}
	var items []listItem
	for _, o := range opts {
		o := o
		items = append(items, listItem{label: o.label, detail: o.f, run: func(m *App) tea.Cmd {
			if apply {
				return m.applyFilter(o.f)
			}
			m.fbar.set(o.f)
			m.focusFilter()
			m.fbarPrev = cur
			return nil
		}})
	}
	return m.push(newList(title, items))
}

func (m *App) applyAsColumn() tea.Cmd {
	n := m.details.current()
	if n == nil || n.Field == nil {
		return m.setFlash(true, "Select a field in the Details pane first")
	}
	f := n.Field
	for _, c := range m.cols {
		if c.Kind == columns.KindCustom && c.Field == f.Abbrev {
			return m.setFlash(true, "There is already a column for %s", f.Abbrev)
		}
	}
	var specs []config.ColumnSpec
	for _, c := range m.cols {
		if c.Kind == columns.KindInfo {
			specs = append(specs, config.ColumnSpec{Title: f.Name, Type: "custom", Field: f.Abbrev})
		}
		specs = append(specs, config.ColumnSpec{Title: c.Title, Type: c.Kind.String(), Field: c.Field, Width: c.Width, Hide: c.Hide})
	}
	m.cfg.Columns = specs
	_ = m.cfg.Save()
	m.setupRows()
	m.list.widths = nil
	return m.setFlash(false, "Added column %q (remove it in %s)", f.Name, m.cfg.Path())
}

func (m *App) conversationFilterMenu() tea.Cmd {
	pi := m.selPI
	if pi == nil {
		return nil
	}
	var items []listItem
	add := func(label, f string) {
		items = append(items, listItem{label: label, detail: f, run: func(m *App) tea.Cmd { return m.applyFilter(f) }})
	}
	if pi.DLSrc.Type == dissect.AddrEther {
		add("Ethernet", fmt.Sprintf("eth.addr == %s && eth.addr == %s", pi.DLSrc, pi.DLDst))
	}
	switch pi.NetSrc.Type {
	case dissect.AddrIPv4:
		add("IPv4", fmt.Sprintf("ip.addr == %s && ip.addr == %s", pi.NetSrc, pi.NetDst))
	case dissect.AddrIPv6:
		add("IPv6", fmt.Sprintf("ipv6.addr == %s && ipv6.addr == %s", pi.NetSrc, pi.NetDst))
	}
	if pi.Conv != nil {
		switch pi.Conv.Type {
		case dissect.ConvTCP:
			add("TCP", fmt.Sprintf("tcp.stream == %d", pi.Conv.Index))
		case dissect.ConvUDP:
			add("UDP", fmt.Sprintf("udp.stream == %d", pi.Conv.Index))
		}
	}
	if len(items) == 0 {
		return m.setFlash(true, "This packet has no conversation")
	}
	return m.push(newList("Conversation Filter", items))
}

func (m *App) contextMenu() tea.Cmd {
	if m.focus == paneDetails {
		items := []listItem{
			{label: "Apply as Filter…", detail: "a", run: func(m *App) tea.Cmd { return m.filterFromFieldMenu(true) }},
			{label: "Prepare as Filter…", detail: "p", run: func(m *App) tea.Cmd { return m.filterFromFieldMenu(false) }},
			{label: "Apply as Column", detail: "A", run: (*App).applyAsColumn},
			{label: "Copy…", detail: "y", run: (*App).copyMenu},
			{label: "Expand Subtrees", detail: "e", run: (*App).expandSubtree},
			{label: "Collapse Subtrees", detail: "w", run: (*App).collapseSubtree},
			{label: "Expand All", detail: "E", run: (*App).expandAll},
			{label: "Collapse All", detail: "W", run: (*App).collapseAll},
		}
		if n := m.details.current(); n != nil && n.Link != 0 {
			link := n.Link
			items = append([]listItem{{label: fmt.Sprintf("Go to Packet %d", link), detail: "enter", run: func(m *App) tea.Cmd { return m.gotoFrame(link) }}}, items...)
		}
		return m.push(newList("Field", items))
	}
	items := []listItem{
		{label: "Mark/Unmark Packet", detail: "m", run: (*App).toggleMark},
		{label: "Ignore/Unignore Packet", detail: "i", run: (*App).toggleIgnore},
		{label: "Set/Unset Time Reference", detail: "t", run: (*App).toggleTimeRef},
		{label: "Packet Comment…", detail: "C", run: (*App).commentDialog},
		{label: "Conversation Filter…", run: (*App).conversationFilterMenu},
		{label: "Copy…", detail: "y", run: (*App).copyMenu},
		{label: "Go to Linked Packet", detail: "^]", run: (*App).gotoLinked},
		{label: "Show Packet Text", run: (*App).packetTab},
		{label: "Export Specified Packets…", run: (*App).exportDialog},
	}
	return m.push(newList(fmt.Sprintf("Packet %d", m.selected), items))
}

// ---- Copy ----

func (m *App) copyMenu() tea.Cmd {
	if m.selPI == nil {
		return nil
	}
	pi := m.selPI
	var items []listItem
	add := func(label, text string) {
		items = append(items, listItem{label: label, detail: preview(text), run: func(m *App) tea.Cmd { return m.copyText(label, text) }})
	}
	if n := m.details.current(); n != nil && m.focus == paneDetails {
		if n.Field != nil {
			if expr, err := m.selectedFieldExpr(); err == nil {
				add("As Filter", expr)
			}
			add("Field Name", n.Field.Abbrev)
			if n.Field.Type != dissect.FtProtocol && n.Field.Type != dissect.FtNone {
				add("Value", n.Field.Display(n.Value))
			}
		}
		add("Description", n.Text())
		if n.Length > 0 && int(n.DS) < len(pi.Sources) {
			b := pi.Sources[n.DS].Data[n.Start : n.Start+n.Length]
			add("Field Bytes as Hex", fmt.Sprintf("%x", b))
		}
		var sub strings.Builder
		sub.WriteString(n.Text() + "\n")
		n.Walk(func(c *dissect.Node, depth int) bool {
			if c.Flags&dissect.NodeHidden == 0 {
				sub.WriteString(strings.Repeat("    ", depth+1) + c.Text() + "\n")
			}
			return true
		})
		add("Item and Subtree as Text", sub.String())
	}
	r := m.row(m.list.cursor)
	add("Summary Line", strings.Join(r.Cells, "\t"))
	var tree strings.Builder
	export.WriteTree(&tree, &pi.Tree.Root)
	add("Packet Details as Text", tree.String())
	data := pi.Sources[0].Data
	var hex strings.Builder
	export.WriteHex(&hex, data)
	add("Bytes as Hex Dump", hex.String())
	add("Bytes as Hex Stream", fmt.Sprintf("%x", data))
	add("Bytes as C Array", cArray(data, m.selected))
	return m.push(newList("Copy", items))
}

func preview(s string) string {
	s = strings.ReplaceAll(s, "\n", " ⏎ ")
	if len([]rune(s)) > 40 {
		return string([]rune(s)[:40]) + "…"
	}
	return s
}

func cArray(b []byte, num uint32) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "static const unsigned char pkt%d[%d] = {\n", num, len(b))
	for i := 0; i < len(b); i += 8 {
		sb.WriteString("  ")
		for j := i; j < i+8 && j < len(b); j++ {
			fmt.Fprintf(&sb, "0x%02x", b[j])
			if j < len(b)-1 {
				sb.WriteString(", ")
			}
		}
		sb.WriteString("\n")
	}
	sb.WriteString("};\n")
	return sb.String()
}

// copyText copies to the system clipboard (pbcopy/wl-copy/xclip when
// running locally) and always via OSC 52 so it also works over SSH.
func (m *App) copyText(what, text string) tea.Cmd {
	local := os.Getenv("SSH_CONNECTION") == ""
	if local {
		for _, c := range [][]string{{"pbcopy"}, {"wl-copy"}, {"xclip", "-selection", "clipboard"}, {"xsel", "-b"}} {
			if _, err := exec.LookPath(c[0]); err == nil {
				cmd := exec.Command(c[0], c[1:]...)
				cmd.Stdin = strings.NewReader(text)
				if cmd.Run() == nil {
					return tea.Batch(tea.SetClipboard(text), m.setFlash(false, "Copied %s", strings.ToLower(what)))
				}
			}
		}
	}
	return tea.Batch(tea.SetClipboard(text), m.setFlash(false, "Copied %s (via terminal clipboard)", strings.ToLower(what)))
}

// ---- Find ----

type findMode uint8

const (
	findFilter findMode = iota
	findString
	findHex
	findRegex
)

type findState struct {
	mode   findMode
	text   string
	filter *dfilter.Filter
	re     *regexp.Regexp
	bytes  []byte
	where  string // "list", "details", "bytes"
}

func (m *App) findDialog() tea.Cmd {
	modes := []struct {
		mode  findMode
		label string
		help  string
	}{
		{findFilter, "Display filter", "e.g. http.request.method == \"POST\""},
		{findString, "String", "case-insensitive text in details, list or bytes"},
		{findHex, "Hex value", "e.g. 16 03 01 or 160301"},
		{findRegex, "Regular expression", "matched against packet details text"},
	}
	var items []listItem
	for _, md := range modes {
		md := md
		items = append(items, listItem{label: md.label, detail: md.help, run: func(m *App) tea.Cmd {
			d := newInput("Find Packet — "+md.label, "Search for:", m.find.text, func(m *App, v string) tea.Cmd {
				if err := m.setFind(md.mode, v); err != nil {
					return m.setFlash(true, "%v", err)
				}
				return m.findNext(1)
			})
			d.validate = func(v string) error {
				if strings.TrimSpace(v) == "" {
					return nil
				}
				var fs findState
				return fs.compile(md.mode, v)
			}
			return m.push(d)
		}})
	}
	return m.push(newList("Find Packet", items))
}

func (f *findState) compile(mode findMode, text string) error {
	*f = findState{mode: mode, text: text}
	switch mode {
	case findFilter:
		flt, err := dfilter.Compile(text)
		if err != nil {
			return err
		}
		f.filter = flt
	case findHex:
		s := strings.NewReplacer(" ", "", ":", "", "-", "").Replace(text)
		if len(s)%2 != 0 {
			return fmt.Errorf("hex values need an even number of digits")
		}
		b := make([]byte, len(s)/2)
		for i := range b {
			v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
			if err != nil {
				return fmt.Errorf("%q is not hex", s[2*i:2*i+2])
			}
			b[i] = byte(v)
		}
		f.bytes = b
	case findRegex:
		re, err := regexp.Compile("(?i)" + text)
		if err != nil {
			return err
		}
		f.re = re
	case findString:
		f.re = regexp.MustCompile("(?i)" + regexp.QuoteMeta(text))
	}
	return nil
}

func (m *App) setFind(mode findMode, text string) error {
	return m.find.compile(mode, text)
}

func (m *App) findNext(dir int) tea.Cmd {
	f := &m.find
	if f.text == "" {
		return m.findDialog()
	}
	var opt dissect.Options
	switch f.mode {
	case findFilter:
		want := make([]bool, dissect.NumFields())
		f.filter.Want(want)
		opt = dissect.Options{Want: want}
	case findString, findRegex:
		opt = dissect.Options{Full: true, Columns: true}
	default:
		opt = dissect.Options{Want: make([]bool, dissect.NumFields())}
	}
	w := m.cap.Session().NewWorker(opt)
	n := len(m.displayed)
	for i := 1; i < n; i++ {
		idx := ((m.list.cursor+dir*i)%n + n) % n
		pi := w.Dissect(m.cap.Input(m.displayed[idx]))
		if m.findMatch(pi) {
			m.pushHistory()
			m.selectIndex(idx)
			m.list.center = true
			wrapped := (dir > 0 && idx < m.list.cursor) || (dir < 0 && idx > m.list.cursor)
			if wrapped {
				return m.setFlash(false, "Search wrapped around")
			}
			return nil
		}
	}
	return m.setFlash(true, "No packet matched %q", f.text)
}

func (m *App) findMatch(pi *dissect.PacketInfo) bool {
	f := &m.find
	switch f.mode {
	case findFilter:
		return f.filter.Match(pi)
	case findHex:
		for _, s := range pi.Sources {
			if strings.Contains(string(s.Data), string(f.bytes)) {
				return true
			}
		}
		return false
	}
	if f.re.MatchString(pi.Info()) || f.re.MatchString(pi.Protocol()) {
		return true
	}
	found := false
	pi.Tree.Root.Walk(func(n *dissect.Node, _ int) bool {
		if !found && f.re.MatchString(n.Text()) {
			found = true
		}
		return !found
	})
	if !found && f.mode == findString {
		for _, s := range pi.Sources {
			if f.re.Match(s.Data) {
				return true
			}
		}
	}
	return found
}

// ---- Tools / Help ----

func (m *App) fieldReference() tea.Cmd {
	var items []listItem
	for _, f := range dissect.Fields() {
		if strings.HasPrefix(f.Abbrev, "_ws.") {
			continue
		}
		f := f
		items = append(items, listItem{label: f.Abbrev, detail: f.Name + " (" + f.Type.String() + ")", run: func(m *App) tea.Cmd {
			if m.cap == nil {
				return m.copyText("field name", f.Abbrev)
			}
			m.focusFilter()
			t := strings.TrimSpace(m.fbar.text())
			if t != "" {
				t += " && "
			}
			m.fbar.set(t + f.Abbrev)
			m.filterChanged()
			return nil
		}})
	}
	d := newList(fmt.Sprintf("Display Filter Fields (%s)", commas(len(items))), items)
	d.filter = true
	d.footer = "enter inserts the field into the filter bar"
	return m.push(d)
}

func (m *App) helpDialog() tea.Cmd {
	var lines []string
	lines = append(lines,
		"lazysniffer — every feature is reachable three ways:",
		"  F10 menu bar (same menus as Wireshark) · ctrl+p command palette · \".\" context menu",
		"",
		"Panes",
		"  tab / shift+tab   next / previous pane       + (or =)  maximize pane",
		"  enter             open details / follow link  esc       back to packet list",
		"  ↑↓ j/k  pgup/pgdn ctrl+u/ctrl+d  g/G          move",
		"",
		"Details pane",
		"  ←/h →/l           collapse / expand          space     toggle",
		"  e / w             expand / collapse subtree  E / W     expand / collapse all",
		"  a / p / A         apply as filter / prepare / apply as column",
		"",
		"Filter bar (/)",
		"  enter apply · esc cancel · tab complete field · ↑↓ history · ctrl+u clear",
		"  Wireshark syntax: tcp.port == 443 && ip.addr == 10.0.0.0/8, http contains \"x\",",
		"  tcp.port in {80 443 8000..8080}, eth.src[0:3] == 00:1a:2b, len(tcp.payload) > 0",
		"",
	)
	for _, menu := range append(menuOrder, "") {
		var rows []string
		for _, a := range m.actions {
			if a.Menu != menu || len(a.Keys) == 0 {
				continue
			}
			keys := strings.Join(a.Keys, ", ")
			rows = append(rows, fmt.Sprintf("  %-20s %s", keys, a.Title))
		}
		if len(rows) == 0 {
			continue
		}
		name := menu
		if name == "" {
			name = "Other"
		}
		lines = append(lines, name)
		lines = append(lines, rows...)
		lines = append(lines, "")
	}
	lines = append(lines, "Settings: "+m.cfg.Path())
	return m.showText("Help", lines)
}

func (m *App) aboutDialog() tea.Cmd {
	return m.showText("About", []string{
		"lazysniffer " + version.String(),
		"",
		"A terminal network protocol analyzer in the spirit of lazygit,",
		"with Wireshark's display filter language and protocol trees.",
		"",
		fmt.Sprintf("Native dissectors: %d protocols, %s fields", len(dissect.Protocols()), commas(dissect.NumFields())),
		"Config: " + config.Dir(),
		"License: MIT",
	})
}
