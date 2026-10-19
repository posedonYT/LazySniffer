package ui

import (
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// tcol is a column of a table tab. A zero width takes the remaining space.
type tcol struct {
	title string
	w     int
	right bool
}

// trow is a table row. keys (optional) are numeric sort keys per column.
type trow struct {
	cells  []string
	keys   []float64
	filter string // display filter selecting the row's packets
	frame  uint32 // packet to go to on enter
	data   any
	indent int
}

// tableSet is one table (statistics windows have one per protocol layer).
type tableSet struct {
	name    string
	cols    []tcol
	rows    []trow
	sortCol int
	desc    bool
	cursor  int
	scroll  scroller
	foot    string
}

// tableTab is a generic sortable table shown as a tab.
type tableTab struct {
	name     string
	subtitle string
	sets     []*tableSet
	cur      int
	extra    [][2]string
	// onKey handles tab specific keys; the row may be nil.
	onKey func(m *App, t *tableTab, row *trow, key string) (tea.Cmd, bool)
	// refresh recomputes the rows (key "r").
	refresh func(m *App, t *tableTab) error
	// noSort disables column sorting (tree-like tables).
	noSort bool
	// onClose runs when the tab closes.
	onClose func(m *App) tea.Cmd
}

func (t *tableTab) title() string { return t.name }

func (t *tableTab) set() *tableSet { return t.sets[t.cur] }

func (t *tableTab) hints() [][2]string {
	h := [][2]string{{"↑↓", "move"}}
	if !t.noSort {
		h = append(h, [2]string{"s", "sort column"}, [2]string{"S", "reverse"})
	}
	if len(t.sets) > 1 {
		h = append(h, [2]string{"tab", "next table"})
	}
	h = append(h, t.extra...)
	if t.refresh != nil {
		h = append(h, [2]string{"r", "refresh"})
	}
	return append(h, [2]string{"esc", "back"})
}

func (t *tableTab) closed(m *App) tea.Cmd {
	if t.onClose != nil {
		return t.onClose(m)
	}
	return nil
}

func (s *tableSet) sortRows() {
	col := s.sortCol
	sort.SliceStable(s.rows, func(i, j int) bool {
		a, b := s.rows[i], s.rows[j]
		var less, eq bool
		if col < len(a.keys) && col < len(b.keys) {
			less, eq = a.keys[col] < b.keys[col], a.keys[col] == b.keys[col]
		} else if col < len(a.cells) && col < len(b.cells) {
			less, eq = strings.ToLower(a.cells[col]) < strings.ToLower(b.cells[col]), a.cells[col] == b.cells[col]
		}
		if eq {
			return false
		}
		return less != s.desc
	})
}

func (t *tableTab) view(m *App, w, h int) string {
	th := m.theme
	s := t.set()
	inner := w - 2
	bodyH := max(h-4, 1)
	if len(t.sets) > 1 {
		bodyH--
	}
	s.scroll.height = bodyH
	if s.cursor < s.scroll.offset {
		s.scroll.offset = s.cursor
	}
	if s.cursor >= s.scroll.offset+bodyH {
		s.scroll.offset = s.cursor - bodyH + 1
	}
	s.scroll.clamp(len(s.rows))
	// column widths
	fixed, flex := 0, 0
	for _, c := range s.cols {
		if c.w > 0 {
			fixed += c.w + 1
		} else {
			flex++
		}
	}
	flexW := 10
	if flex > 0 {
		flexW = max((inner-fixed-1)/flex-1, 8)
	}
	widths := make([]int, len(s.cols))
	for i, c := range s.cols {
		widths[i] = c.w
		if c.w == 0 {
			widths[i] = flexW
		}
	}
	line := func(cells []string, indent int) string {
		var b strings.Builder
		b.WriteString(" ")
		for i, c := range s.cols {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			if i == 0 && indent > 0 {
				cell = strings.Repeat("  ", indent) + cell
			}
			if c.right {
				b.WriteString(fitRight(cell, widths[i]))
			} else {
				b.WriteString(fit(cell, widths[i]))
			}
			b.WriteString(" ")
		}
		return b.String()
	}
	hdrCells := make([]string, len(s.cols))
	for i, c := range s.cols {
		hdrCells[i] = c.title
		if !t.noSort && i == s.sortCol {
			if s.desc {
				hdrCells[i] += " ▼"
			} else {
				hdrCells[i] += " ▲"
			}
		}
	}
	var body []string
	if len(t.sets) > 1 {
		var tabs []string
		for i, st := range t.sets {
			label := " " + st.name + " "
			if i == t.cur {
				tabs = append(tabs, lipgloss.NewStyle().Background(th.Accent).Foreground(th.SelFG).Bold(true).Render(label))
			} else {
				tabs = append(tabs, lipgloss.NewStyle().Foreground(th.Muted).Render(label))
			}
		}
		body = append(body, fit(strings.Join(tabs, " "), inner))
	}
	body = append(body, fit(lipgloss.NewStyle().Foreground(th.Muted).Bold(true).Render(line(hdrCells, 0)), inner))
	for i := s.scroll.offset; i < len(s.rows) && len(body) < bodyH+1+btoiTab(len(t.sets) > 1); i++ {
		r := s.rows[i]
		st := lipgloss.NewStyle().Foreground(th.Text)
		if i == s.cursor {
			st = st.Background(th.SelBG).Foreground(th.SelFG)
		}
		body = append(body, fit(st.Render(fit(line(r.cells, r.indent), inner)), inner))
	}
	if len(s.rows) == 0 {
		body = append(body, lipgloss.NewStyle().Foreground(th.Muted).Render("  Nothing to show"))
	}
	for len(body) < h-3 {
		body = append(body, "")
	}
	foot := s.foot
	if foot == "" {
		foot = commas(len(s.rows)) + " rows"
	}
	body = append(body, fit(lipgloss.NewStyle().Foreground(th.Muted).Render(" "+foot), inner))
	return m.box(t.name, t.subtitle, body, w, h, true)
}

func btoiTab(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (t *tableTab) key(m *App, key string) (tea.Cmd, bool) {
	s := t.set()
	n := len(s.rows)
	var row *trow
	if s.cursor < n {
		row = &s.rows[s.cursor]
	}
	if t.onKey != nil {
		if cmd, ok := t.onKey(m, t, row, key); ok {
			return cmd, true
		}
	}
	switch key {
	case "up", "k":
		s.cursor = max(s.cursor-1, 0)
	case "down", "j":
		s.cursor = min(s.cursor+1, max(n-1, 0))
	case "pgup":
		s.cursor = max(s.cursor-s.scroll.height, 0)
	case "pgdown", "space":
		s.cursor = min(s.cursor+s.scroll.height, max(n-1, 0))
	case "home", "g":
		s.cursor = 0
	case "end", "G":
		s.cursor = max(n-1, 0)
	case "tab":
		if len(t.sets) > 1 {
			t.cur = (t.cur + 1) % len(t.sets)
		}
	case "shift+tab":
		if len(t.sets) > 1 {
			t.cur = (t.cur + len(t.sets) - 1) % len(t.sets)
		}
	case "s":
		if t.noSort {
			return nil, false
		}
		s.sortCol = (s.sortCol + 1) % len(s.cols)
		s.sortRows()
	case "S":
		if t.noSort {
			return nil, false
		}
		s.desc = !s.desc
		s.sortRows()
	case "a":
		if row != nil && row.filter != "" {
			m.tab = -1
			return m.applyFilter(row.filter), true
		}
	case "p":
		if row != nil && row.filter != "" {
			m.tab = -1
			m.fbar.set(row.filter)
			return m.focusFilter(), true
		}
	case "enter":
		if row != nil && row.frame != 0 {
			m.tab = -1
			return m.gotoFrame(row.frame), true
		}
		if row != nil && row.filter != "" {
			m.tab = -1
			return m.applyFilter(row.filter), true
		}
	case "r":
		if t.refresh != nil {
			if err := t.refresh(m, t); err != nil {
				return m.setFlash(true, "%v", err), true
			}
		}
	case "esc", "q":
		return m.closeTab(m.tab), true
	default:
		return nil, false
	}
	return nil, true
}

// openUniqueTab switches to an existing tab of the same name or opens t.
func (m *App) openUniqueTab(t *tableTab) {
	for i, o := range m.tabs {
		if ot, ok := o.(*tableTab); ok && ot.name == t.name {
			m.tabs[i] = t
			m.tab = i
			return
		}
	}
	m.openTab(t)
}
