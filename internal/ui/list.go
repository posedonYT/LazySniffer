package ui

import (
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/poseydon/lazysniffer/internal/columns"
	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/store"
)

type listState struct {
	cursor  int
	offset  int
	hscroll int
	widths  map[int]int // grown-only auto widths per column index
	center  bool
	bodyH   int
}

func (m *App) visibleCols() []int {
	var idx []int
	for i, c := range m.cols {
		if !c.Hide {
			idx = append(idx, i)
		}
	}
	return idx
}

func colCap(c columns.Column) int {
	if c.Width > 0 {
		return c.Width
	}
	switch c.Kind {
	case columns.KindSource, columns.KindDestination:
		return 39
	case columns.KindProtocol:
		return 10
	case columns.KindProcess:
		return 16
	case columns.KindCustom:
		return 32
	case columns.KindTime:
		return 30
	}
	return 12
}

func (m *App) renderList(w, h int, focused bool) string {
	inner := w - 2
	bodyH := max(h-3, 1)
	m.list.bodyH = bodyH
	n := len(m.displayed)
	l := &m.list
	if l.cursor >= n {
		l.cursor = max(n-1, 0)
	}
	if l.center {
		l.offset = l.cursor - bodyH/2
		l.center = false
	}
	if l.cursor < l.offset {
		l.offset = l.cursor
	}
	if l.cursor >= l.offset+bodyH {
		l.offset = l.cursor - bodyH + 1
	}
	l.offset = max(min(l.offset, n-bodyH), 0)

	vis := m.visibleCols()
	end := min(l.offset+bodyH, n)
	rows := make([]columns.Row, 0, end-l.offset)
	for i := l.offset; i < end; i++ {
		rows = append(rows, m.row(i))
	}
	// Column widths grow to fit the visible rows and never shrink while
	// scrolling, so the table does not jitter.
	if l.widths == nil {
		l.widths = map[int]int{}
	}
	infoIdx := -1
	for _, ci := range vis {
		c := m.cols[ci]
		if c.Kind == columns.KindInfo {
			infoIdx = ci
			continue
		}
		wd := max(l.widths[ci], ansi.StringWidth(c.Title))
		if c.Kind == columns.KindNumber {
			wd = max(wd, len(strconv.Itoa(m.cap.Count())))
		}
		for _, r := range rows {
			if ci < len(r.Cells) {
				wd = max(wd, ansi.StringWidth(r.Cells[ci]))
			}
		}
		wd = min(wd, colCap(c))
		l.widths[ci] = wd
	}

	gutter := 2
	vis = m.dropColumns(vis, inner-gutter)
	header := strings.Repeat(" ", gutter) + m.joinCells(vis, func(ci int) string { return m.cols[ci].Title }, inner-gutter)
	hs := lipgloss.NewStyle().Foreground(m.theme.Muted).Bold(true)
	body := []string{hs.Render(fit(cut(header, l.hscroll), inner))}
	for i, r := range rows {
		idx := l.offset + i
		line := m.joinCells(vis, func(ci int) string {
			if ci < len(r.Cells) {
				return r.Cells[ci]
			}
			return ""
		}, inner-gutter)
		line = cut(line, l.hscroll)
		body = append(body, m.styleRow(r, idx == l.cursor, focused, fit(line, inner-gutter), gutter))
	}
	if n == 0 {
		msg := "No packets"
		switch {
		case m.loading:
			msg = "Loading…"
		case m.filtering:
			msg = "Filtering…"
		case m.filter != nil && !m.filter.Empty():
			msg = "No packets match the display filter. Press ctrl+x to clear it."
		}
		body = append(body, "", lipgloss.PlaceHorizontal(inner, lipgloss.Center, lipgloss.NewStyle().Foreground(m.theme.Muted).Render(msg)))
	}
	_ = infoIdx
	title := "Packets"
	right := ""
	if n > 0 {
		right = commas(l.cursor+1) + "/" + commas(n)
	}
	return m.box(title, right, body, w, h, focused)
}

// dropColumns hides less important columns on narrow terminals so the Info
// column keeps at least a third of the width.
func (m *App) dropColumns(vis []int, width int) []int {
	order := []columns.Kind{columns.KindLength, columns.KindProcess, columns.KindCustom, columns.KindTime, columns.KindProtocol}
	fixed := func(v []int) int {
		n := 0
		for k, ci := range v {
			if k > 0 {
				n += 2
			}
			if m.cols[ci].Kind != columns.KindInfo {
				n += m.list.widths[ci]
			}
		}
		return n
	}
	for _, kind := range order {
		if fixed(vis) <= width*2/3 {
			break
		}
		var keep []int
		for _, ci := range vis {
			if m.cols[ci].Kind != kind {
				keep = append(keep, ci)
			}
		}
		vis = keep
	}
	return vis
}

func (m *App) joinCells(vis []int, cell func(ci int) string, width int) string {
	var b strings.Builder
	used := 0
	for k, ci := range vis {
		c := m.cols[ci]
		s := cell(ci)
		if k > 0 {
			b.WriteString("  ")
			used += 2
		}
		if c.Kind == columns.KindInfo {
			b.WriteString(s)
			used += ansi.StringWidth(s)
			continue
		}
		wd := m.list.widths[ci]
		if wd == 0 {
			wd = ansi.StringWidth(c.Title)
		}
		if c.Right {
			b.WriteString(fitRight(s, wd))
		} else {
			b.WriteString(fit(s, wd))
		}
		used += wd
	}
	_ = used
	_ = width
	return b.String()
}

func (m *App) styleRow(r columns.Row, selected, focused bool, line string, gutter int) string {
	t := m.theme
	st := lipgloss.NewStyle().Foreground(t.Text)
	flags := m.cap.Frame(r.Num).Flags
	g := []rune("  ")
	if flags&store.FlagComment != 0 {
		g[1] = '✎'
	}
	gs := lipgloss.NewStyle()
	switch {
	case r.Sev >= dissect.SevError:
		g[0] = '●'
		gs = gs.Foreground(t.Err)
	case r.Sev == dissect.SevWarn:
		g[0] = '●'
		gs = gs.Foreground(t.Warn)
	}
	switch {
	case selected:
		bg := t.SelDimBG
		fg := t.Text
		if focused {
			bg, fg = t.SelBG, t.SelFG
		}
		st = st.Background(bg).Foreground(fg).Bold(true)
		gs = gs.Background(bg)
		if g[0] == ' ' {
			g[0] = '▶'
			gs = gs.Foreground(fg)
		}
	case flags&store.FlagMarked != 0:
		st = st.Background(t.MarkedBG).Foreground(t.MarkedFG)
	case flags&store.FlagIgnored != 0:
		st = st.Foreground(t.Muted).Faint(true)
	case m.colorize && r.Color >= 0 && r.Color < len(m.colorRules):
		cr := m.colorRules[r.Color]
		if m.cfg.ColorStyle == "foreground" {
			st = st.Foreground(cr.textColor(t.Dark))
		} else {
			st = st.Background(cr.bg).Foreground(cr.fg)
		}
	}
	return gs.Render(string(g)) + st.Render(line)
}

func (m *App) listKey(key string) (tea.Cmd, bool) {
	l := &m.list
	n := len(m.displayed)
	move := func(d int) {
		if n == 0 {
			return
		}
		m.selectIndex(max(min(l.cursor+d, n-1), 0))
	}
	switch key {
	case "up", "k":
		move(-1)
	case "down", "j":
		move(1)
	case "pgup", "ctrl+b":
		move(-max(l.bodyH-1, 1))
	case "pgdown", "ctrl+f", "space":
		if key == "ctrl+f" {
			return nil, false
		}
		move(max(l.bodyH-1, 1))
	case "ctrl+u":
		move(-max(l.bodyH/2, 1))
	case "ctrl+d":
		move(max(l.bodyH/2, 1))
	case "left", "h":
		l.hscroll = max(l.hscroll-8, 0)
	case "right", "l":
		l.hscroll += 8
	case "0":
		l.hscroll = 0
	case "enter":
		if m.selPI != nil {
			m.setFocus(paneDetails)
		}
	default:
		return nil, false
	}
	return nil, true
}

func (m *App) listMoveTo(idx int) tea.Cmd {
	if len(m.displayed) == 0 {
		return nil
	}
	m.selectIndex(max(min(idx, len(m.displayed)-1), 0))
	return nil
}
