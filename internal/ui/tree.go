package ui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/poseydon/lazysniffer/internal/dissect"
)

type treeItem struct {
	n     *dissect.Node
	depth int
}

type treeState struct {
	expanded map[string]bool
	items    []treeItem
	cursor   int
	offset   int
	selKey   string
	bodyH    int
	root     *dissect.Node
}

func (t *treeState) reset() {
	exp := t.expanded
	*t = treeState{expanded: exp}
	if t.expanded == nil {
		t.expanded = map[string]bool{}
	}
}

// nodeKey identifies a tree item across packets so expansion state and
// the selected field survive moving to another packet.
func nodeKey(n *dissect.Node) string {
	var parts []string
	for c := n; c != nil && c.Parent != nil; c = c.Parent {
		parts = append(parts, itemKey(c))
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, "/")
}

func itemKey(n *dissect.Node) string {
	if n.Field != nil {
		return n.Field.Abbrev
	}
	s := n.Text()
	if i := strings.IndexAny(s, ":("); i > 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func (t *treeState) load(m *App, pi *dissect.PacketInfo) {
	if t.expanded == nil {
		t.expanded = map[string]bool{}
	}
	t.root = &pi.Tree.Root
	t.rebuild()
	// Restore the previously selected field if this packet has it.
	t.cursor = 0
	if t.selKey != "" {
		for i, it := range t.items {
			if nodeKey(it.n) == t.selKey {
				t.cursor = i
				break
			}
		}
	}
}

func (t *treeState) rebuild() {
	t.items = t.items[:0]
	if t.root == nil {
		return
	}
	var walk func(n *dissect.Node, depth int)
	walk = func(n *dissect.Node, depth int) {
		for c := n.First; c != nil; c = c.Next {
			if c.Flags&dissect.NodeHidden != 0 {
				continue
			}
			t.items = append(t.items, treeItem{c, depth})
			if c.HasChildren() && t.expanded[nodeKey(c)] {
				walk(c, depth+1)
			}
		}
	}
	walk(t.root, 0)
	if t.cursor >= len(t.items) {
		t.cursor = max(len(t.items)-1, 0)
	}
}

func (t *treeState) current() *dissect.Node {
	if t.cursor < 0 || t.cursor >= len(t.items) {
		return nil
	}
	return t.items[t.cursor].n
}

func (t *treeState) setExpanded(n *dissect.Node, on bool) {
	k := nodeKey(n)
	if on {
		t.expanded[k] = true
	} else {
		delete(t.expanded, k)
	}
	t.rebuild()
}

func (t *treeState) setSubtree(n *dissect.Node, on bool) {
	var rec func(x *dissect.Node)
	rec = func(x *dissect.Node) {
		if x.HasChildren() {
			if on {
				t.expanded[nodeKey(x)] = true
			} else {
				delete(t.expanded, nodeKey(x))
			}
		}
		for c := x.First; c != nil; c = c.Next {
			rec(c)
		}
	}
	rec(n)
	t.rebuild()
}

func (m *App) renderDetails(w, h int, focused bool) string {
	t := &m.details
	inner := w - 2
	bodyH := max(h-2, 1)
	t.bodyH = bodyH
	if t.cursor < t.offset {
		t.offset = t.cursor
	}
	if t.cursor >= t.offset+bodyH {
		t.offset = t.cursor - bodyH + 1
	}
	t.offset = max(min(t.offset, len(t.items)-bodyH), 0)
	var body []string
	th := m.theme
	for i := t.offset; i < len(t.items) && len(body) < bodyH; i++ {
		it := t.items[i]
		n := it.n
		marker := "  "
		if n.HasChildren() {
			if t.expanded[nodeKey(n)] {
				marker = "▼ "
			} else {
				marker = "▶ "
			}
		}
		text := n.Text()
		st := lipgloss.NewStyle().Foreground(th.Text)
		switch {
		case n.Expert != nil:
			st = st.Foreground(th.Sev[min(int(n.Expert.Def.Severity), 5)])
		case n.Link != 0:
			st = st.Foreground(th.Link).Underline(true)
		case n.Flags&dissect.NodeGenerated != 0:
			st = st.Foreground(th.Generated)
		}
		if it.depth == 0 {
			st = st.Bold(true)
		}
		line := strings.Repeat("  ", it.depth) + marker + text
		if i == t.cursor {
			bg := th.SelDimBG
			fg := th.Text
			if focused {
				bg, fg = th.SelBG, th.SelFG
			}
			st = st.Background(bg).Foreground(fg)
			body = append(body, st.Render(fit(line, inner)))
			continue
		}
		body = append(body, st.Render(fit(line, inner)))
	}
	if m.selPI == nil {
		body = append(body, lipgloss.NewStyle().Foreground(th.Muted).Render("Select a packet to see its protocol tree"))
	}
	right := ""
	if n := t.current(); n != nil && n.Field != nil {
		right = n.Field.Abbrev
	}
	return m.box("Details", right, body, w, h, focused)
}

func (m *App) treeKey(key string) (tea.Cmd, bool) {
	t := &m.details
	n := len(t.items)
	if n == 0 {
		return nil, false
	}
	move := func(i int) {
		t.cursor = max(min(i, n-1), 0)
		if cur := t.current(); cur != nil {
			t.selKey = nodeKey(cur)
		}
		m.bytes.syncToNode(m)
	}
	cur := t.current()
	switch key {
	case "up", "k":
		move(t.cursor - 1)
	case "down", "j":
		move(t.cursor + 1)
	case "pgup", "ctrl+b":
		move(t.cursor - max(t.bodyH-1, 1))
	case "pgdown", "space":
		if key == "space" && cur != nil && cur.HasChildren() {
			t.setExpanded(cur, !t.expanded[nodeKey(cur)])
			return nil, true
		}
		move(t.cursor + max(t.bodyH-1, 1))
	case "ctrl+u":
		move(t.cursor - max(t.bodyH/2, 1))
	case "ctrl+d":
		move(t.cursor + max(t.bodyH/2, 1))
	case "home", "g":
		move(0)
	case "end", "G":
		move(n - 1)
	case "left", "h":
		if cur == nil {
			break
		}
		if cur.HasChildren() && t.expanded[nodeKey(cur)] {
			t.setExpanded(cur, false)
			break
		}
		// Jump to the parent item.
		for i := t.cursor - 1; i >= 0; i-- {
			if t.items[i].depth < t.items[t.cursor].depth {
				move(i)
				break
			}
		}
	case "right", "l":
		if cur == nil || !cur.HasChildren() {
			break
		}
		if !t.expanded[nodeKey(cur)] {
			t.setExpanded(cur, true)
		} else {
			move(t.cursor + 1)
		}
	case "enter":
		if cur == nil {
			break
		}
		if cur.Link != 0 {
			return m.gotoFrame(cur.Link), true
		}
		if cur.HasChildren() {
			t.setExpanded(cur, !t.expanded[nodeKey(cur)])
		}
	default:
		return nil, false
	}
	return nil, true
}

func (m *App) expandSubtree() tea.Cmd {
	if n := m.details.current(); n != nil {
		m.details.setSubtree(n, true)
	}
	return nil
}

func (m *App) collapseSubtree() tea.Cmd {
	if n := m.details.current(); n != nil {
		m.details.setSubtree(n, false)
	}
	return nil
}

func (m *App) expandAll() tea.Cmd {
	if m.details.root != nil {
		m.details.setSubtree(m.details.root, true)
	}
	return nil
}

func (m *App) collapseAll() tea.Cmd {
	m.details.expanded = map[string]bool{}
	m.details.rebuild()
	return nil
}

// gotoLinked follows the selected field's frame link ([Response in: N]).
func (m *App) gotoLinked() tea.Cmd {
	if n := m.details.current(); n != nil && n.Link != 0 {
		return m.gotoFrame(n.Link)
	}
	// Otherwise look for any link in the packet.
	if m.selPI != nil {
		var link uint32
		m.selPI.Tree.Root.Walk(func(n *dissect.Node, _ int) bool {
			if link == 0 && n.Link != 0 {
				link = n.Link
			}
			return link == 0
		})
		if link != 0 {
			return m.gotoFrame(link)
		}
	}
	return m.setFlash(true, "This packet has no linked packet")
}
