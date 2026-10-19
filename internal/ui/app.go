package ui

import (
	"context"
	"fmt"
	"github.com/poseydon/lazysniffer/internal/deep"
	"github.com/poseydon/lazysniffer/internal/resolve"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/poseydon/lazysniffer/internal/capture"
	"github.com/poseydon/lazysniffer/internal/columns"
	"github.com/poseydon/lazysniffer/internal/config"
	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/store"
	"github.com/poseydon/lazysniffer/internal/version"
)

type pane uint8

const (
	paneList pane = iota
	paneDetails
	paneBytes
	paneFilter
)

// Options configure the application at start.
type Options struct {
	Path          string
	Filter        string
	Ifaces        []string // start capturing on these ("-" = stdin)
	CaptureFilter string
	SSH           string // user@host[:iface]
	// Exec runs a command once the capture started (lazysniffer run -- cmd).
	// The command gets SSLKEYLOGFILE=KeylogFile so its TLS can be decrypted.
	Exec       []string
	KeylogFile string
	KeepOpen   bool // keep capturing after the command exits
	LuaErrors  []error
}

// App is the root Bubble Tea model.
type App struct {
	refreshAfterLoad bool
	deepc            *deep.Client
	deepFiltered     bool
	execStarted      bool
	w, h             int
	theme            *Theme
	themeOK          bool // background detected
	cfg              *config.Config
	actions          []*Action
	opts             Options

	// Capture state.
	cap        *store.Capture
	rows       *columns.Builder
	cols       []columns.Column
	rowCache   map[uint32]columns.Row
	displayed  []uint32
	loading    bool
	loadProg   store.Progress
	loadCancel context.CancelFunc
	loadCh     chan tea.Msg
	loadErr    error
	openedAt   time.Time

	// Filtering.
	filter       *dfilter.Filter
	filterGen    int
	filtering    bool
	filterDone   int
	filterCancel context.CancelFunc
	filterCh     chan tea.Msg
	fbar         lineEdit
	fbarErr      *dfilter.Error
	fbarWarn     string
	fbarPrev     string
	suggest      []*dissect.FieldDef
	suggestIdx   int
	histIdx      int
	colorRules   []colorRule
	colorize     bool

	// Panes.
	focus      pane
	zoom       bool
	single     pane // shown pane in single-pane layout
	list       listState
	details    treeState
	bytes      hexState
	selected   uint32
	selPI      *dissect.PacketInfo
	history    []uint32
	histPos    int
	autoScroll bool

	// Overlays.
	startIdx   int
	dnsVersion int64
	menuOpen   int // -1 closed; index into menuOrder
	menuIdx    int
	menuItems  []*Action
	palette    *paletteState
	dialogs    []dialog

	capt captureState

	// Analysis tabs (Follow Stream, Expert Info…); tab -1 is the packet list.
	tabs []tabView
	tab  int

	expertMax     dissect.Severity
	expertScanned int

	// Status.
	flash     string
	flashErr  bool
	flashTime time.Time
	find      findState

	// Layout regions for mouse hit-testing (set while rendering).
	rList, rDetails, rBytes, rFilter, rMenu rect
	menuX                                   []int
	tabX                                    []int
}

// New creates the application model.
func New(cfg *config.Config, opts Options) *App {
	m := &App{cfg: cfg, opts: opts, menuOpen: -1, colorize: cfg.ColorRows, autoScroll: true, tab: -1}
	applyProtocolPrefs(cfg)
	resolve.LoadGeoIP(cfg.GeoIPDir)
	m.theme = NewTheme(cfg.Theme != "light")
	m.buildActions()
	m.applyResolution()
	m.loadColorRules()
	m.fbar.set(opts.Filter)
	m.initCapture()
	if opts.CaptureFilter != "" {
		m.capt.opts.Filter = opts.CaptureFilter
	}
	return m
}

type flashMsg struct{}

type dnsTickMsg struct{}

// dnsTick refreshes rows when reverse DNS answers arrive.
func (m *App) dnsTick() tea.Cmd {
	if !m.cfg.ResolveNetwork {
		return nil
	}
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return dnsTickMsg{} })
}

// flashDuration is how long status messages stay visible.
var flashDuration = 4 * time.Second

// Init implements tea.Model.
func (m *App) Init() tea.Cmd {
	cmds := []tea.Cmd{tea.RequestBackgroundColor, m.dnsTick(), m.onIfaceTick()}
	switch {
	case m.opts.Path == "-" || len(m.opts.Ifaces) == 1 && m.opts.Ifaces[0] == "-":
		cmds = append(cmds, m.startStdin())
	case m.opts.SSH != "":
		host, iface, _ := strings.Cut(m.opts.SSH, ":")
		cmds = append(cmds, m.startSSH(capture.SSHOptions{Host: host, Iface: iface, Filter: m.capt.opts.Filter}))
	case len(m.opts.Ifaces) > 0:
		o := m.capt.opts
		o.Ifaces = m.opts.Ifaces
		if len(o.Ifaces) > 1 {
			o.PKTAP = false
		}
		cmds = append(cmds, m.startCapture(o))
	case m.opts.Path != "":
		cmds = append(cmds, m.openFile(m.opts.Path))
	}
	return tea.Batch(cmds...)
}

// Update implements tea.Model.
func (m *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil
	case tea.BackgroundColorMsg:
		if m.cfg.Theme == "auto" || m.cfg.Theme == "" {
			m.theme = NewTheme(msg.IsDark())
			m.rowCache = nil
		}
		return m, nil
	case loadMsg:
		return m, m.onLoad(msg)
	case liveEventMsg:
		return m, m.onLiveEvent(msg)
	case execDoneMsg:
		return m, m.onExecDone(msg)
	case liveTickMsg:
		return m, m.onLiveTick(msg)
	case ifaceTickMsg:
		return m, m.onIfaceTick()
	case filterMsg:
		return m, m.onFilter(msg)
	case deepFilterMsg:
		return m, m.onDeepFilter(msg)
	case colorRulesEditedMsg:
		m.loadColorRules()
		m.setupRows()
		if msg.err != nil {
			return m, m.setFlash(true, "Editor: %v", msg.err)
		}
		return m, m.setFlash(false, "Reloaded %d coloring rules", len(m.colorRules))
	case dnsTickMsg:
		if v := dns.Version(); v != m.dnsVersion {
			m.dnsVersion = v
			m.rowCache = nil
		}
		return m, m.dnsTick()
	case flashMsg:
		if time.Since(m.flashTime) >= flashDuration {
			m.flash = ""
		}
		return m, nil
	case tea.PasteMsg:
		if m.focus == paneFilter {
			m.fbar.insert(strings.ReplaceAll(msg.Content, "\n", " "))
			m.filterChanged()
			return m, nil
		}
		if len(m.dialogs) > 0 {
			return m, m.dialogs[len(m.dialogs)-1].paste(m, msg.Content)
		}
		return m, nil
	case tea.KeyPressMsg:
		return m, m.onKey(msg)
	case tea.MouseClickMsg:
		return m, m.onClick(msg.Mouse())
	case tea.MouseWheelMsg:
		return m, m.onWheel(msg.Mouse())
	}
	return m, nil
}

func (m *App) setFlash(err bool, format string, args ...any) tea.Cmd {
	m.flash = fmt.Sprintf(format, args...)
	m.flashErr = err
	m.flashTime = time.Now()
	return tea.Tick(flashDuration, func(time.Time) tea.Msg { return flashMsg{} })
}

func (m *App) onKey(k tea.KeyPressMsg) tea.Cmd {
	key := k.String()
	// Overlays take keys first.
	if len(m.dialogs) > 0 {
		return m.dialogs[len(m.dialogs)-1].key(m, k)
	}
	if m.palette != nil {
		return m.paletteKey(k)
	}
	if m.menuOpen >= 0 {
		return m.menuKey(k)
	}
	if m.focus == paneFilter {
		return m.filterKey(k)
	}
	if m.cap != nil {
		if cmd, ok := m.tabKey(key); ok {
			return cmd
		}
		if t := m.currentTab(); t != nil {
			if cmd, ok := t.key(m, key); ok {
				return cmd
			}
			// Unhandled keys fall through to global actions.
			if a := m.findAction(key); a != nil && a.Ctx&ctxGlobal != 0 {
				return a.Run(m)
			}
			return nil
		}
	}
	// Pane navigation keys.
	if m.cap != nil {
		switch key {
		case "tab":
			m.cycleFocus(1)
			return nil
		case "shift+tab":
			m.cycleFocus(-1)
			return nil
		case "esc":
			if m.zoom {
				m.zoom = false
				return nil
			}
			if m.focus != paneList {
				m.setFocus(paneList)
				return nil
			}
			return nil
		}
		var cmd tea.Cmd
		handled := false
		switch m.focus {
		case paneList:
			cmd, handled = m.listKey(key)
		case paneDetails:
			cmd, handled = m.treeKey(key)
		case paneBytes:
			cmd, handled = m.hexKey(key)
		}
		if handled {
			return cmd
		}
	} else if cmd, ok := m.startKey(key); ok {
		return cmd
	}
	if a := m.findAction(key); a != nil {
		return a.Run(m)
	}
	return nil
}

func (m *App) panesShown() []pane {
	if m.cap == nil {
		return nil
	}
	if m.zoom || m.layoutMode() == layoutSingle {
		return []pane{m.focusOrList()}
	}
	return []pane{paneList, paneDetails, paneBytes}
}

func (m *App) focusOrList() pane {
	if m.focus == paneFilter {
		return m.single
	}
	return m.focus
}

func (m *App) setFocus(p pane) {
	if p != paneFilter {
		m.single = p
	}
	m.focus = p
}

func (m *App) cycleFocus(d int) {
	order := []pane{paneList, paneDetails, paneBytes}
	i := 0
	for j, p := range order {
		if p == m.focus {
			i = j
		}
	}
	i = (i + d + len(order)) % len(order)
	m.setFocus(order[i])
}

type layoutKind uint8

const (
	layoutWide layoutKind = iota
	layoutStacked
	layoutSingle
)

func (m *App) layoutMode() layoutKind {
	switch {
	case m.w >= 180 && m.h >= 24:
		return layoutWide
	case m.w >= 100 && m.h >= 30:
		return layoutStacked
	case m.h >= 36 && m.w >= 60:
		return layoutStacked
	}
	return layoutSingle
}

// View implements tea.Model.
func (m *App) View() tea.View {
	var v tea.View
	v.AltScreen = true
	if m.cfg.Mouse {
		v.MouseMode = tea.MouseModeCellMotion
	}
	v.WindowTitle = m.windowTitle()
	if m.w == 0 || m.h == 0 {
		v.SetContent("")
		return v
	}
	if m.w < 40 || m.h < 10 {
		v.SetContent(lipgloss.Place(m.w, m.h, lipgloss.Center, lipgloss.Center, "Terminal too small\n(need at least 40×10)"))
		return v
	}
	base := m.render()
	if over := m.overlays(); len(over) > 0 {
		layers := append([]*lipgloss.Layer{lipgloss.NewLayer(base)}, over...)
		base = lipgloss.NewCanvas(m.w, m.h).Compose(lipgloss.NewCompositor(layers...)).Render()
	}
	v.SetContent(base)
	if m.loading || m.filtering {
		v.ProgressBar = m.progressBar()
	}
	return v
}

func (m *App) windowTitle() string {
	if m.cap == nil {
		return "lazysniffer"
	}
	return "lazysniffer — " + baseName(m.cap.Path)
}

func (m *App) progressBar() *tea.ProgressBar {
	pct := 0
	switch {
	case m.loading && m.loadProg.Total > 0:
		pct = int(m.loadProg.Bytes * 100 / m.loadProg.Total)
	case m.filtering && len(m.allFrames()) > 0:
		pct = m.filterDone * 100 / max(m.cap.Count(), 1)
	}
	return tea.NewProgressBar(tea.ProgressBarDefault, pct)
}

func (m *App) render() string {
	menu := m.renderMenuBar()
	if m.cap == nil {
		body := m.renderStart(m.w, m.h-3)
		return joinV(menu, body, m.renderStatus(), m.renderHints())
	}
	fbar := m.renderFilterBar()
	tabs := m.renderTabBar()
	mainH := m.h - 4
	top := 2
	if tabs != "" {
		mainH--
		top++
	}
	var body string
	if t := m.currentTab(); t != nil {
		m.rList, m.rDetails, m.rBytes = rect{}, rect{}, rect{}
		body = t.view(m, m.w, mainH)
	} else {
		body = m.renderPanes(m.w, mainH, top)
	}
	return joinV(menu, fbar, tabs, body, m.renderStatus(), m.renderHints())
}

func (m *App) renderPanes(w, h, y int) string {
	if m.zoom || m.layoutMode() == layoutSingle {
		p := m.focusOrList()
		return m.renderPane(p, 0, y, w, h)
	}
	switch m.layoutMode() {
	case layoutWide:
		listH := max(h*48/100, 6)
		botH := h - listH
		detW := w * 55 / 100
		top := m.renderPane(paneList, 0, y, w, listH)
		left := m.renderPane(paneDetails, 0, y+listH, detW, botH)
		right := m.renderPane(paneBytes, detW, y+listH, w-detW, botH)
		return joinV(top, joinH(left, right))
	default:
		listH := max(h*42/100, 6)
		bytesH := max(h*22/100, 5)
		detH := h - listH - bytesH
		return joinV(
			m.renderPane(paneList, 0, y, w, listH),
			m.renderPane(paneDetails, 0, y+listH, w, detH),
			m.renderPane(paneBytes, 0, y+listH+detH, w, bytesH),
		)
	}
}

func (m *App) renderPane(p pane, x, y, w, h int) string {
	r := rect{x, y, w, h}
	focused := m.focus == p || (m.focus == paneFilter && p == paneList && m.single == paneList)
	switch p {
	case paneDetails:
		m.rDetails = r
		return m.renderDetails(w, h, focused)
	case paneBytes:
		m.rBytes = r
		return m.renderBytes(w, h, focused)
	}
	m.rList = r
	return m.renderList(w, h, focused)
}

func (m *App) renderStatus() string {
	st := lipgloss.NewStyle().Background(m.theme.BarBG).Foreground(m.theme.BarFG)
	var left, right string
	switch {
	case m.cap == nil:
		left = st.Render(" Ready. Open a capture file to start.")
	default:
		parts := []string{" " + baseName(m.cap.Path)}
		if ls := m.liveStatus(); ls != "" {
			parts[0] = " " + lipgloss.NewStyle().Foreground(m.theme.Err).Background(m.theme.BarBG).Bold(true).Render(ls)
		} else if m.capt.unsaved {
			parts[0] += " (unsaved)"
		}
		total := m.cap.Count()
		if m.loading {
			pct := 0
			if m.loadProg.Total > 0 {
				pct = int(m.loadProg.Bytes * 100 / m.loadProg.Total)
			}
			parts = append(parts, fmt.Sprintf("Loading %d%%", pct))
		}
		parts = append(parts, fmt.Sprintf("Packets: %s", commas(total)))
		if m.filter != nil && !m.filter.Empty() {
			pct := 0.0
			if total > 0 {
				pct = float64(len(m.displayed)) * 100 / float64(total)
			}
			parts = append(parts, fmt.Sprintf("Displayed: %s (%.1f%%)", commas(len(m.displayed)), pct))
		}
		if m.filtering {
			parts = append(parts, fmt.Sprintf("Filtering %d%%", m.filterDone*100/max(total, 1)))
		}
		if n := len(m.cap.FramesWithFlag(store.FlagMarked)); n > 0 {
			parts = append(parts, fmt.Sprintf("Marked: %d", n))
		}
		if n := len(m.cap.FramesWithFlag(store.FlagIgnored)); n > 0 {
			parts = append(parts, fmt.Sprintf("Ignored: %d", n))
		}
		if sev := m.updateExpertMax(); sev >= dissect.SevNote {
			parts = append(parts, lipgloss.NewStyle().Background(m.theme.BarBG).Foreground(m.theme.Sev[sev]).Render("● Expert: "+sev.String())+st.Render(" (!)"))
		}
		if m.loadErr != nil {
			parts = append(parts, "Error: "+m.loadErr.Error())
		} else if m.cap.Truncated() {
			parts = append(parts, "File is cut short")
		}
		left = st.Render(strings.Join(parts, " │ "))
	}
	right = st.Foreground(m.theme.Muted).Render("lazysniffer " + version.Version + " ")
	if m.flash != "" {
		fs := st.Foreground(m.theme.OK)
		if m.flashErr {
			fs = st.Foreground(m.theme.Err)
		}
		room := max(m.w-lipgloss.Width(left)-3, 10)
		right = fs.Render(fit(m.flash, min(lipgloss.Width(m.flash), room)) + " ")
	}
	gap := m.w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		return fit(left, m.w)
	}
	return left + st.Render(strings.Repeat(" ", gap)) + right
}

func (m *App) renderHints() string {
	var hints []string
	add := func(k, l string) { hints = append(hints, m.keyHint(k, l)) }
	switch {
	case len(m.dialogs) > 0:
		add("enter", "confirm")
		add("esc", "cancel")
		add("↑↓", "select")
	case m.palette != nil:
		add("type", "search")
		add("enter", "run")
		add("esc", "close")
	case m.menuOpen >= 0:
		add("←→", "menus")
		add("↑↓", "items")
		add("enter", "run")
		add("esc", "close")
	case m.currentTab() != nil && m.focus != paneFilter:
		for _, hnt := range m.currentTab().hints() {
			add(hnt[0], hnt[1])
		}
		add("[ ]", "tabs")
	case m.focus == paneFilter:
		add("enter", "apply")
		add("tab", "complete")
		add("↑↓", "history")
		add("esc", "cancel")
		add("ctrl+u", "clear")
	case m.cap == nil:
		if m.capt.startFocus == 0 {
			add("enter", "start capture")
			add("space", "select")
			add("f", "capture filter")
			add("K", "options")
			add("S", "ssh")
		} else {
			add("enter", "open")
		}
		add("tab", "interfaces/files")
		add("o", "open file")
		add("ctrl+p", "commands")
		add("f10", "menu")
		add("?", "help")
		add("q", "quit")
	case m.focus == paneDetails:
		add("↑↓", "move")
		add("←→", "collapse/expand")
		add("a", "apply as filter")
		add("p", "prepare")
		add("A", "column")
		add("e/E", "expand")
		add("y", "copy")
		add("tab", "next pane")
		add("?", "help")
	case m.focus == paneBytes:
		add("←↑↓→", "move")
		add("b", "bits/hex")
		add("d", "data source")
		add("y", "copy")
		add("tab", "next pane")
		add("?", "help")
	default:
		add("↑↓", "move")
		add("enter", "details")
		add("/", "filter")
		if m.capt.live != nil {
			add("c", "stop capture")
		}
		add("m", "mark")
		add("t", "time ref")
		add(".", "menu")
		add("ctrl+p", "commands")
		add("f10", "menu bar")
		add("?", "help")
		add("q", "quit")
	}
	line := " " + strings.Join(hints, "  ")
	return fit(line, m.w)
}

// updateExpertMax tracks the highest expert severity seen in the capture.
func (m *App) updateExpertMax() dissect.Severity {
	if m.cap == nil {
		return 0
	}
	n := m.cap.Count()
	if n < m.expertScanned {
		m.expertScanned, m.expertMax = 0, 0
	}
	for i := m.expertScanned + 1; i <= n; i++ {
		if s := dissect.Severity(m.cap.Frame(uint32(i)).MaxSev); s > m.expertMax {
			m.expertMax = s
		}
	}
	m.expertScanned = n
	return m.expertMax
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func commas(n int) string {
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}
