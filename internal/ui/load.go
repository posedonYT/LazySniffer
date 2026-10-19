package ui

import (
	"context"
	"errors"
	"github.com/poseydon/lazysniffer/internal/deep"
	"net/netip"
	"os"
	"sort"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/poseydon/lazysniffer/internal/columns"
	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/store"
)

type loadMsg struct {
	cap  *store.Capture
	prog store.Progress
	done bool
	err  error
}

type filterMsg struct {
	gen    int
	frames []uint32
	done   bool
	n      int
	err    error
	text   string
	filter *dfilter.Filter
}

func listen(ch chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return nil
		}
		return msg
	}
}

// openFile closes the current capture and starts loading path.
func (m *App) openFile(path string) tea.Cmd {
	if m.capt.unsaved && m.cap != nil {
		return m.askSaveThen(func(m *App) tea.Cmd { return m.openFileWith(path, false) })
	}
	return m.openFileWith(path, false)
}

func (m *App) openFileWith(path string, live bool) tea.Cmd {
	if _, err := os.Stat(path); err != nil {
		return m.setFlash(true, "%v", err)
	}
	c, err := store.Open(path)
	if err != nil {
		return m.setFlash(true, "Cannot open %s: %v", baseName(path), err)
	}
	m.closeCurrent()
	m.cap = c
	c.Live = live
	if !live {
		m.cfg.AddRecent(path)
		_ = m.cfg.Save()
		m.capt.unsaved, m.capt.tempFile = false, ""
	}
	for _, nr := range c.File().Names {
		if a, ok := netip.AddrFromSlice(nr.Addr); ok && len(nr.Names) > 0 {
			dns.AddStatic(a, nr.Names[0])
		}
	}
	m.openedAt = time.Now()
	m.displayed = nil
	m.rowCache = nil
	m.selected, m.selPI = 0, nil
	m.list = listState{}
	m.details.reset()
	m.bytes = hexState{}
	m.history, m.histPos = nil, 0
	m.focus, m.single, m.zoom = paneList, paneList, false
	m.loadErr = nil
	m.expertMax, m.expertScanned = 0, 0
	m.tabs, m.tab = nil, -1
	m.setupRows()
	ctx, cancel := context.WithCancel(context.Background())
	m.loadCancel = cancel
	m.loading = true
	ch := make(chan tea.Msg, 4)
	m.loadCh = ch
	go func() {
		err := c.Load(ctx, func(p store.Progress) {
			select {
			case ch <- loadMsg{cap: c, prog: p}:
			default:
			}
		})
		ch <- loadMsg{cap: c, prog: store.Progress{Frames: c.Count()}, done: true, err: err}
		close(ch)
	}()
	return listen(ch)
}

func (m *App) closeCurrent() {
	if m.loadCancel != nil {
		m.loadCancel()
		m.loadCancel = nil
	}
	if m.filterCancel != nil {
		m.filterCancel()
		m.filterCancel = nil
	}
	if m.cap != nil {
		m.cap.Close()
		m.cap = nil
	}
	m.closeDeep()
	m.deepFiltered = false
	m.loading, m.filtering = false, false
}

func (m *App) onLoad(msg loadMsg) tea.Cmd {
	if msg.cap != m.cap {
		return nil // stale message from a closed capture
	}
	m.loadProg = msg.prog
	if !msg.done {
		if m.filter == nil || m.filter.Empty() {
			m.extendDisplayed()
		}
		return listen(m.loadCh)
	}
	m.loading = false
	if msg.err != nil && !errors.Is(msg.err, context.Canceled) {
		m.loadErr = msg.err
	}
	if m.filter == nil && m.fbar.text() != "" {
		return m.applyFilter(m.fbar.text())
	}
	if m.filter != nil && !m.filter.Empty() {
		return m.runFilter(m.filter)
	}
	m.extendDisplayed()
	if m.selected == 0 && len(m.displayed) > 0 {
		m.selectIndex(0)
	}
	if m.refreshAfterLoad {
		// The capture ended (or grew) while the first load was running.
		m.refreshAfterLoad = false
		m.refreshLive()
	}
	if m.cap.Live {
		return nil
	}
	return m.setFlash(false, "Loaded %s packets in %s", commas(m.cap.Count()), time.Since(m.openedAt).Round(time.Millisecond))
}

// extendDisplayed appends newly loaded frames when no filter is active.
func (m *App) extendDisplayed() {
	n := m.cap.Count()
	for i := len(m.displayed) + 1; i <= n; i++ {
		m.displayed = append(m.displayed, uint32(i))
	}
	if m.selected == 0 && len(m.displayed) > 0 {
		m.selectIndex(0)
	}
}

func (m *App) allFrames() []uint32 { return m.displayed }

// setupRows builds the column/row renderer for the current capture.
func (m *App) setupRows() {
	if m.cap == nil {
		return
	}
	m.cols = m.columnsFromConfig()
	b := columns.NewBuilder(m.cap, m.cols)
	b.Precision = m.cfg.TimePrecision
	b.Time = parseTimeFormat(m.cfg.TimeFormat)
	b.ResolveAddr = m.resolveAddr
	var extra []*dissect.FieldDef
	for _, r := range m.colorRules {
		if r.filter != nil {
			extra = append(extra, r.filter.Fields...)
		}
	}
	b.Extra = extra
	b.Colorize = m.colorIndex
	b.Process = m.processFor
	b.Rebuild()
	m.rows = b
	m.rowCache = nil
}

func (m *App) columnsFromConfig() []columns.Column {
	var cols []columns.Column
	if len(m.cfg.Columns) > 0 {
		for _, c := range m.cfg.Columns {
			k, ok := columns.ParseKind(c.Type)
			if !ok {
				continue
			}
			cols = append(cols, columns.Column{Title: c.Title, Kind: k, Type: c.Type, Field: c.Field, Width: c.Width, Hide: c.Hide,
				Right: k == columns.KindNumber || k == columns.KindTime || k == columns.KindLength})
		}
	}
	if len(cols) == 0 {
		cols = columns.Defaults()
		for i := range cols {
			cols[i].Type = cols[i].Kind.String()
			if cols[i].Kind == columns.KindProcess {
				cols[i].Hide = !m.cfg.ShowProcess
			}
		}
	}
	return cols
}

func parseTimeFormat(s string) columns.TimeFormat {
	switch s {
	case "absolute":
		return columns.TimeAbsolute
	case "absolute_date":
		return columns.TimeAbsoluteDate
	case "utc":
		return columns.TimeUTC
	case "utc_date":
		return columns.TimeUTCDate
	case "epoch":
		return columns.TimeEpoch
	case "delta":
		return columns.TimeDeltaCaptured
	case "delta_displayed":
		return columns.TimeDeltaDisplayed
	}
	return columns.TimeRelative
}

func timeFormatName(f columns.TimeFormat) string {
	switch f {
	case columns.TimeAbsolute:
		return "absolute"
	case columns.TimeAbsoluteDate:
		return "absolute_date"
	case columns.TimeUTC:
		return "utc"
	case columns.TimeUTCDate:
		return "utc_date"
	case columns.TimeEpoch:
		return "epoch"
	case columns.TimeDeltaCaptured:
		return "delta"
	case columns.TimeDeltaDisplayed:
		return "delta_displayed"
	}
	return "relative"
}

// row returns the cached packet-list row of frame num.
func (m *App) row(idx int) columns.Row {
	num := m.displayed[idx]
	if r, ok := m.rowCache[num]; ok {
		return r
	}
	if m.rowCache == nil || len(m.rowCache) > 20000 {
		m.rowCache = map[uint32]columns.Row{}
	}
	prev := uint32(0)
	if idx > 0 {
		prev = m.displayed[idx-1]
	}
	r := m.rows.Row(num, prev)
	m.rowCache[num] = r
	return r
}

// applyFilter compiles text and starts filtering. An invalid filter is
// reported and nothing changes.
func (m *App) applyFilter(text string) tea.Cmd {
	f, err := dfilter.Compile(text)
	if err != nil {
		var fe *dfilter.Error
		if errors.As(err, &fe) {
			if fe.Unknown != "" && m.cap != nil && deep.Available() {
				return m.runDeepFilter(text) // a field only Wireshark knows
			}
			m.fbarErr = fe
		}
		return m.setFlash(true, "Invalid filter: %v", err)
	}
	m.deepFiltered = false
	m.fbar.set(text)
	m.fbarErr = nil
	m.cfg.AddFilterHistory(text)
	_ = m.cfg.Save()
	if m.cap == nil {
		return nil
	}
	if m.loading {
		m.filter = f
		return m.setFlash(false, "The filter will be applied when loading finishes")
	}
	return m.runFilter(f)
}

func (m *App) runFilter(f *dfilter.Filter) tea.Cmd {
	if m.filterCancel != nil {
		m.filterCancel()
	}
	m.filterGen++
	gen := m.filterGen
	f.SetRefs(m.selPI)
	ctx, cancel := context.WithCancel(context.Background())
	m.filterCancel = cancel
	m.filtering, m.filterDone = true, 0
	c := m.cap
	ch := make(chan tea.Msg, 4)
	m.filterCh = ch
	start := time.Now()
	go func() {
		frames, err := engine.Filter(ctx, c, f, 1, uint32(c.Count()), func(done int) {
			select {
			case ch <- filterMsg{gen: gen, n: done}:
			default:
			}
		})
		_ = start
		ch <- filterMsg{gen: gen, frames: frames, done: true, err: err, filter: f}
		close(ch)
	}()
	return listen(ch)
}

func (m *App) onFilter(msg filterMsg) tea.Cmd {
	if msg.gen != m.filterGen {
		return nil
	}
	if !msg.done {
		m.filterDone = msg.n
		return listen(m.filterCh)
	}
	m.filtering = false
	if msg.err != nil {
		if errors.Is(msg.err, context.Canceled) {
			return nil
		}
		return m.setFlash(true, "Filter failed: %v", msg.err)
	}
	m.filter = msg.filter
	prevSel := m.selected
	m.displayed = msg.frames
	m.rowCache = nil
	// Keep the selection if it is still displayed, else select the nearest.
	idx := sort.Search(len(m.displayed), func(i int) bool { return m.displayed[i] >= prevSel })
	switch {
	case len(m.displayed) == 0:
		m.selected, m.selPI = 0, nil
		m.list.cursor = 0
	case idx < len(m.displayed):
		m.selectIndex(idx)
	default:
		m.selectIndex(len(m.displayed) - 1)
	}
	m.list.center = true
	if m.filter.Empty() {
		return nil
	}
	return m.setFlash(false, "Displayed %s of %s packets", commas(len(m.displayed)), commas(m.cap.Count()))
}

// selectIndex selects the displayed row idx and dissects it fully.
func (m *App) selectIndex(idx int) {
	if idx < 0 || idx >= len(m.displayed) {
		return
	}
	m.list.cursor = idx
	num := m.displayed[idx]
	if num == m.selected && m.selPI != nil {
		return
	}
	m.selected = num
	m.dissectSelected()
}

func (m *App) dissectSelected() {
	if m.cap == nil || m.selected == 0 {
		m.selPI = nil
		return
	}
	w := m.cap.Session().NewWorker(dissect.Options{Full: true, Columns: true})
	fi := m.cap.Input(m.selected)
	if fi == nil {
		return
	}
	m.selPI = w.Dissect(fi)
	m.details.load(m, m.selPI)
	m.bytes.syncToNode(m)
}

// gotoFrame selects frame num if it is displayed; it records history.
func (m *App) gotoFrame(num uint32) tea.Cmd {
	idx := sort.Search(len(m.displayed), func(i int) bool { return m.displayed[i] >= num })
	if idx >= len(m.displayed) || m.displayed[idx] != num {
		return m.setFlash(true, "Packet %d is not displayed", num)
	}
	m.pushHistory()
	m.selectIndex(idx)
	m.list.center = true
	return nil
}

func (m *App) pushHistory() {
	if m.selected == 0 {
		return
	}
	m.history = append(m.history[:m.histPos], m.selected)
	m.histPos = len(m.history)
}

func (m *App) historyMove(d int) tea.Cmd {
	if d < 0 {
		if m.histPos == 0 {
			return m.setFlash(true, "No previous packet in history")
		}
		if m.histPos == len(m.history) {
			m.history = append(m.history, m.selected)
		}
		m.histPos--
	} else {
		if m.histPos+1 >= len(m.history) {
			return m.setFlash(true, "No next packet in history")
		}
		m.histPos++
	}
	num := m.history[m.histPos]
	idx := sort.Search(len(m.displayed), func(i int) bool { return m.displayed[i] >= num })
	if idx < len(m.displayed) && m.displayed[idx] == num {
		m.selectIndex(idx)
		m.list.center = true
	}
	return nil
}
