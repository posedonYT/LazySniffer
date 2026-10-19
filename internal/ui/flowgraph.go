package ui

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/engine"
)

const flowMaxRows = 4000
const flowMaxCols = 6

type flowRow struct {
	frame    uint32
	ts       float64
	src, dst int
	label    string
	proto    string
	sev      dissect.Severity
}

type flowTab struct {
	cols    []string
	rows    []flowRow
	cursor  int
	scroll  scroller
	all     bool
	clipped bool
}

func (f *flowTab) title() string { return "Flow Graph" }

func (f *flowTab) closed(*App) tea.Cmd { return nil }

func (f *flowTab) hints() [][2]string {
	scope := "displayed"
	if f.all {
		scope = "all packets"
	}
	return [][2]string{{"↑↓", "move"}, {"enter", "go to packet"}, {"a", "scope: " + scope}, {"esc", "back"}}
}

func (m *App) openFlowGraph() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	f := &flowTab{}
	f.build(m)
	m.openUniqueFlow(f)
	return nil
}

func (m *App) openUniqueFlow(f *flowTab) {
	for i, t := range m.tabs {
		if _, ok := t.(*flowTab); ok {
			m.tabs[i] = f
			m.tab = i
			return
		}
	}
	m.openTab(f)
}

func (f *flowTab) build(m *App) {
	frames := m.displayed
	if f.all || len(frames) == 0 {
		frames = engine.AllFrames(m.cap)
	}
	f.clipped = len(frames) > flowMaxRows
	if f.clipped {
		frames = frames[:flowMaxRows]
	}
	rows := make([]flowRow, 0, len(frames))
	addr := map[string]int{}
	var cols []string
	idx := func(a dissect.Address) int {
		s := a.String()
		if i, ok := addr[s]; ok {
			return i
		}
		if len(cols) >= flowMaxCols {
			return -1
		}
		addr[s] = len(cols)
		cols = append(cols, s)
		return len(cols) - 1
	}
	// Dissect sequentially so that rows keep frame order.
	w := m.cap.Session().NewWorker(dissect.Options{Columns: true, Want: make([]bool, dissect.NumFields())})
	for _, num := range frames {
		fi := m.cap.Input(num)
		if fi == nil {
			continue
		}
		pi := w.Dissect(fi)
		src, dst := pi.Src, pi.Dst
		if src.IsZero() {
			src, dst = pi.NetSrc, pi.NetDst
		}
		if src.IsZero() {
			src, dst = pi.DLSrc, pi.DLDst
		}
		if src.IsZero() {
			continue
		}
		si, di := idx(src), idx(dst)
		if si < 0 || di < 0 {
			continue
		}
		rows = append(rows, flowRow{frame: num, ts: float64(pi.RelTS) / 1e9, src: si, dst: di, label: pi.Info(), proto: pi.Protocol(), sev: pi.MaxSeverity})
	}
	f.cols, f.rows = cols, rows
	f.cursor = min(f.cursor, max(len(rows)-1, 0))
}

func (f *flowTab) view(m *App, w, h int) string {
	th := m.theme
	inner := w - 2
	n := max(len(f.cols), 1)
	timeW := 11
	colW := max((inner-timeW-14)/n, 8)
	bodyH := max(h-5, 1)
	f.scroll.height = bodyH
	if f.cursor < f.scroll.offset {
		f.scroll.offset = f.cursor
	}
	if f.cursor >= f.scroll.offset+bodyH {
		f.scroll.offset = f.cursor - bodyH + 1
	}
	f.scroll.clamp(len(f.rows))
	muted := lipgloss.NewStyle().Foreground(th.Muted)
	head := fit(" Time", timeW)
	for _, c := range f.cols {
		head += fit(center(c, colW), colW)
	}
	body := []string{muted.Bold(true).Render(fit(head, inner))}
	for i := f.scroll.offset; i < len(f.rows) && len(body) < bodyH+1; i++ {
		r := f.rows[i]
		cells := make([]rune, colW*n)
		for j := range cells {
			cells[j] = ' '
		}
		for c := 0; c < n; c++ {
			cells[c*colW+colW/2] = '│'
		}
		lo, hi := min(r.src, r.dst), max(r.src, r.dst)
		x0, x1 := lo*colW+colW/2, hi*colW+colW/2
		if r.src == r.dst {
			x0, x1 = lo*colW+colW/2, lo*colW+colW/2+4
		}
		for x := x0; x <= x1 && x < len(cells); x++ {
			cells[x] = '─'
		}
		switch {
		case r.src < r.dst:
			cells[x1] = '▶'
			cells[x0] = '├'
		case r.src > r.dst:
			cells[x0] = '◀'
			cells[x1] = '┤'
		}
		// label centered on the arrow
		lab := []rune(" " + r.label + " ")
		room := x1 - x0 - 1
		if r.src == r.dst {
			room = 0
		}
		if room > 2 {
			if len(lab) > room {
				lab = append(lab[:room-1], '…')
			}
			start := x0 + 1 + (room-len(lab))/2
			copy(cells[start:], lab)
		}
		line := fit(fmt.Sprintf(" %9.4f ", r.ts), timeW) + string(cells)
		if r.src == r.dst || room <= 2 {
			line += " " + r.label
		}
		st := lipgloss.NewStyle().Foreground(th.Text)
		if r.sev >= dissect.SevWarn {
			st = lipgloss.NewStyle().Foreground(th.Sev[min(int(r.sev), 5)])
		}
		if i == f.cursor {
			st = st.Background(th.SelBG).Foreground(th.SelFG)
		}
		body = append(body, st.Render(fit(line, inner)))
	}
	for len(body) < h-3 {
		body = append(body, "")
	}
	foot := fmt.Sprintf(" %s flows · %s", commas(len(f.rows)), strings.Join(f.cols, " · "))
	if f.clipped {
		foot += fmt.Sprintf(" · limited to the first %d packets", flowMaxRows)
	}
	body = append(body, muted.Render(fit(foot, inner)))
	return m.box("Flow Graph", map[bool]string{true: "all packets", false: "displayed packets"}[f.all], body, w, h, true)
}

func center(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return strings.Repeat(" ", (w-len(s))/2) + s
}

func (f *flowTab) key(m *App, key string) (tea.Cmd, bool) {
	n := len(f.rows)
	switch key {
	case "up", "k":
		f.cursor = max(f.cursor-1, 0)
	case "down", "j":
		f.cursor = min(f.cursor+1, max(n-1, 0))
	case "pgup":
		f.cursor = max(f.cursor-f.scroll.height, 0)
	case "pgdown", "space":
		f.cursor = min(f.cursor+f.scroll.height, max(n-1, 0))
	case "home", "g":
		f.cursor = 0
	case "end", "G":
		f.cursor = max(n-1, 0)
	case "a":
		f.all = !f.all
		f.build(m)
	case "r":
		f.build(m)
	case "enter":
		if f.cursor < n {
			m.tab = -1
			return m.gotoFrame(f.rows[f.cursor].frame), true
		}
	case "esc", "q":
		return m.closeTab(m.tab), true
	default:
		return nil, false
	}
	return nil, true
}

var _ = context.Background
