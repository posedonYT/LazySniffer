package ui

import (
	"context"
	"fmt"
	"sort"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/engine"
)

type expertItem struct {
	frame uint32
	msg   string
}

type expertGroup struct {
	def   *dissect.ExpertField
	proto string
	items []expertItem
}

type expertRow struct {
	group int
	item  int // -1 for the group header
}

type expertTab struct {
	groups   []expertGroup
	expanded map[int]bool
	rows     []expertRow
	cursor   int
	scroll   scroller
	limit    bool // limit to the display filter
	minSev   dissect.Severity
	counts   map[dissect.Severity]int
}

func (e *expertTab) title() string { return "Expert Info" }

func (e *expertTab) hints() [][2]string {
	lim := "all packets"
	if e.limit {
		lim = "displayed only"
	}
	return [][2]string{{"↑↓", "move"}, {"enter", "expand / go to packet"}, {"a", "apply as filter"},
		{"d", lim}, {"s", "min severity: " + e.minSev.String()}, {"r", "refresh"}, {"esc", "back"}}
}

func (e *expertTab) closed(*App) tea.Cmd { return nil }

func (m *App) openExpert() tea.Cmd {
	for i, t := range m.tabs {
		if _, ok := t.(*expertTab); ok {
			m.tab = i
			return nil
		}
	}
	e := &expertTab{expanded: map[int]bool{}, minSev: dissect.SevChat}
	if err := e.collect(m); err != nil {
		return m.setFlash(true, "Expert Info: %v", err)
	}
	m.openTab(e)
	return nil
}

func (e *expertTab) collect(m *App) error {
	frames := engine.AllFrames(m.cap)
	if e.limit {
		frames = m.displayed
	}
	type key struct{ id dissect.FieldID }
	parts := make([]map[key]*expertGroup, engine.Workers())
	for i := range parts {
		parts[i] = map[key]*expertGroup{}
	}
	err := engine.Each(context.Background(), m.cap, dissect.Options{Want: make([]bool, dissect.NumFields())}, frames,
		func(w int, num uint32, pi *dissect.PacketInfo) {
			for _, ex := range pi.Experts {
				k := key{ex.Def.F.ID}
				g := parts[w][k]
				if g == nil {
					proto := ""
					if ex.Proto != nil {
						proto = ex.Proto.Short
					}
					g = &expertGroup{def: ex.Def, proto: proto}
					parts[w][k] = g
				}
				g.items = append(g.items, expertItem{frame: num, msg: ex.Msg})
			}
		})
	if err != nil {
		return err
	}
	merged := map[key]*expertGroup{}
	for _, p := range parts {
		for k, g := range p {
			if mg := merged[k]; mg != nil {
				mg.items = append(mg.items, g.items...)
			} else {
				merged[k] = g
			}
		}
	}
	e.groups = e.groups[:0]
	e.counts = map[dissect.Severity]int{}
	for _, g := range merged {
		sort.Slice(g.items, func(i, j int) bool { return g.items[i].frame < g.items[j].frame })
		e.groups = append(e.groups, *g)
		e.counts[g.def.Severity] += len(g.items)
	}
	sort.Slice(e.groups, func(i, j int) bool {
		a, b := e.groups[i], e.groups[j]
		if a.def.Severity != b.def.Severity {
			return a.def.Severity > b.def.Severity
		}
		if len(a.items) != len(b.items) {
			return len(a.items) > len(b.items)
		}
		return a.def.Summary < b.def.Summary
	})
	e.rebuild()
	return nil
}

func (e *expertTab) rebuild() {
	e.rows = e.rows[:0]
	for gi, g := range e.groups {
		if g.def.Severity < e.minSev {
			continue
		}
		e.rows = append(e.rows, expertRow{group: gi, item: -1})
		if e.expanded[gi] {
			for ii := range g.items {
				e.rows = append(e.rows, expertRow{group: gi, item: ii})
			}
		}
	}
	if e.cursor >= len(e.rows) {
		e.cursor = max(len(e.rows)-1, 0)
	}
}

func (e *expertTab) view(m *App, w, h int) string {
	th := m.theme
	inner := w - 2
	bodyH := max(h-4, 1)
	e.scroll.height = bodyH
	if e.cursor < e.scroll.offset {
		e.scroll.offset = e.cursor
	}
	if e.cursor >= e.scroll.offset+bodyH {
		e.scroll.offset = e.cursor - bodyH + 1
	}
	e.scroll.clamp(len(e.rows))
	sumW := max(inner-48, 20)
	head := lipgloss.NewStyle().Foreground(th.Muted).Bold(true).Render(
		fit("  Severity", 12) + fit("Summary", sumW) + fit("Group", 14) + fit("Protocol", 10) + fitRight("Count", 8))
	body := []string{fit(head, inner)}
	for i := e.scroll.offset; i < len(e.rows) && len(body) < bodyH+1; i++ {
		r := e.rows[i]
		g := e.groups[r.group]
		sev := lipgloss.NewStyle().Foreground(th.Sev[min(int(g.def.Severity), 5)])
		st := lipgloss.NewStyle().Foreground(th.Text)
		if i == e.cursor {
			st = st.Background(th.SelBG).Foreground(th.SelFG)
			sev = sev.Background(th.SelBG)
		}
		var line string
		if r.item < 0 {
			mark := "▶ "
			if e.expanded[r.group] {
				mark = "▼ "
			}
			line = sev.Render(mark+fit(g.def.Severity.String(), 10)) +
				st.Render(fit(g.def.Summary, sumW)+fit(g.def.Group.String(), 14)+fit(g.proto, 10)+fitRight(commas(len(g.items)), 8))
		} else {
			it := g.items[r.item]
			line = st.Render(fit(fmt.Sprintf("      #%-8d %s", it.frame, it.msg), inner))
		}
		body = append(body, fit(line, inner))
	}
	if len(e.rows) == 0 {
		body = append(body, lipgloss.NewStyle().Foreground(th.Muted).Render("  No expert information at this severity"))
	}
	for len(body) < h-3 {
		body = append(body, "")
	}
	var parts []string
	for _, s := range []dissect.Severity{dissect.SevError, dissect.SevWarn, dissect.SevNote, dissect.SevChat, dissect.SevComment} {
		if n := e.counts[s]; n > 0 {
			parts = append(parts, lipgloss.NewStyle().Foreground(th.Sev[s]).Render(fmt.Sprintf("● %s: %s", s, commas(n))))
		}
	}
	foot := " "
	for i, p := range parts {
		if i > 0 {
			foot += "   "
		}
		foot += p
	}
	body = append(body, fit(foot, inner))
	scope := "all packets"
	if e.limit {
		scope = "limited to display filter"
	}
	return m.box("Expert Information", scope, body, w, h, true)
}

func (e *expertTab) key(m *App, key string) (tea.Cmd, bool) {
	n := len(e.rows)
	cur := func() *expertRow {
		if e.cursor < n {
			return &e.rows[e.cursor]
		}
		return nil
	}
	switch key {
	case "up", "k":
		e.cursor = max(e.cursor-1, 0)
	case "down", "j":
		e.cursor = min(e.cursor+1, max(n-1, 0))
	case "pgup":
		e.cursor = max(e.cursor-e.scroll.height, 0)
	case "pgdown", "space":
		e.cursor = min(e.cursor+e.scroll.height, max(n-1, 0))
	case "home", "g":
		e.cursor = 0
	case "end", "G":
		e.cursor = max(n-1, 0)
	case "right", "l":
		if r := cur(); r != nil && r.item < 0 {
			e.expanded[r.group] = true
			e.rebuild()
		}
	case "left", "h":
		if r := cur(); r != nil {
			g := r.group
			e.expanded[g] = false
			e.rebuild()
			for i, row := range e.rows {
				if row.group == g && row.item < 0 {
					e.cursor = i
				}
			}
		}
	case "enter":
		r := cur()
		if r == nil {
			return nil, true
		}
		if r.item < 0 {
			e.expanded[r.group] = !e.expanded[r.group]
			e.rebuild()
			return nil, true
		}
		fr := e.groups[r.group].items[r.item].frame
		m.tab = -1
		return m.gotoFrame(fr), true
	case "a":
		if r := cur(); r != nil {
			return m.applyFilter(e.groups[r.group].def.F.Abbrev), true
		}
	case "d":
		e.limit = !e.limit
		e.collect(m)
	case "s":
		order := []dissect.Severity{dissect.SevComment, dissect.SevChat, dissect.SevNote, dissect.SevWarn, dissect.SevError}
		for i, s := range order {
			if s == e.minSev {
				e.minSev = order[(i+1)%len(order)]
				break
			}
		}
		e.rebuild()
	case "r":
		e.collect(m)
	case "esc", "q":
		return m.closeTab(m.tab), true
	default:
		return nil, false
	}
	return nil, true
}
