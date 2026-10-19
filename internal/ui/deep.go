package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/poseydon/lazysniffer/internal/deep"
	"github.com/poseydon/lazysniffer/internal/dfilter"
)

// deepErrMsg is the explanation shown when Wireshark is missing.
const deepMissing = "The deep engine needs Wireshark's sharkd (brew install wireshark / apt install tshark)"

// ensureDeep starts sharkd if needed and makes sure it has the current
// capture file loaded (live captures are reloaded every time).
func (m *App) ensureDeep() (*deep.Client, error) {
	if m.cap == nil {
		return nil, fmt.Errorf("no capture is open")
	}
	if !deep.Available() {
		return nil, fmt.Errorf("%s", deepMissing)
	}
	if m.deepc == nil {
		c, err := deep.Start()
		if err != nil {
			return nil, err
		}
		m.deepc = c
	}
	if m.deepc.File != m.cap.Path || m.cap.Live {
		if err := m.deepc.Load(m.cap.Path); err != nil {
			return nil, err
		}
	}
	return m.deepc, nil
}

func (m *App) closeDeep() {
	if m.deepc != nil {
		m.deepc.Close()
		m.deepc = nil
	}
}

type deepFilterMsg struct {
	text   string
	frames []uint32
	err    error
}

// runDeepFilter filters with Wireshark's engine (fields lazysniffer does
// not implement natively).
func (m *App) runDeepFilter(text string) tea.Cmd {
	c, err := m.ensureDeep()
	if err != nil {
		return m.setFlash(true, "Invalid filter: %v", err)
	}
	m.fbar.set(text)
	m.cfg.AddFilterHistory(text)
	_ = m.cfg.Save()
	m.filtering, m.filterDone = true, 0
	return func() tea.Msg {
		if err := c.Check(text); err != nil {
			return deepFilterMsg{text: text, err: err}
		}
		frames, err := c.Frames(text)
		return deepFilterMsg{text: text, frames: frames, err: err}
	}
}

func (m *App) onDeepFilter(msg deepFilterMsg) tea.Cmd {
	m.filtering = false
	if msg.err != nil {
		return m.setFlash(true, "Invalid filter: %v", msg.err)
	}
	f, _ := dfilter.Compile("frame.number > 0")
	f.Text = msg.text
	m.filter = f
	m.displayed = msg.frames
	m.rowCache = nil
	m.deepFiltered = true
	switch {
	case len(m.displayed) == 0:
		m.selected, m.selPI = 0, nil
		m.list.cursor = 0
	default:
		m.selectIndex(0)
	}
	m.list.center = true
	return m.setFlash(false, "deep filter (Wireshark): displayed %s of %s packets", commas(len(m.displayed)), commas(m.cap.Count()))
}

// ---- Deep dissection tab ----

type deepRow struct {
	n     *deep.Node
	depth int
}

type deepTab struct {
	frame    uint32
	data     *deep.Frame
	expanded map[*deep.Node]bool
	rows     []deepRow
	cursor   int
	scroll   scroller
}

func (t *deepTab) title() string { return fmt.Sprintf("Deep %d", t.frame) }

func (t *deepTab) closed(*App) tea.Cmd { return nil }

func (t *deepTab) hints() [][2]string {
	return [][2]string{{"↑↓", "move"}, {"→/←", "expand/collapse"}, {"e/E", "expand all / collapse"}, {"a", "apply as filter"}, {"p", "prepare"}, {"y", "copy"}, {"esc", "back"}}
}

func (m *App) openDeepFrame() tea.Cmd {
	if m.cap == nil || m.selected == 0 {
		return m.setFlash(true, "Select a packet first")
	}
	c, err := m.ensureDeep()
	if err != nil {
		return m.setFlash(true, "%v", err)
	}
	fr, err := c.Frame(m.selected)
	if err != nil {
		return m.setFlash(true, "Deep dissection: %v", err)
	}
	t := &deepTab{frame: m.selected, data: fr, expanded: map[*deep.Node]bool{}}
	t.rebuild() // protocols start collapsed, like Wireshark
	t.cursor = max(len(t.rows)-1, 0)
	m.openTab(t)
	return nil
}

func (t *deepTab) rebuild() {
	t.rows = t.rows[:0]
	var rec func(ns []*deep.Node, d int)
	rec = func(ns []*deep.Node, d int) {
		for _, n := range ns {
			if n.Hidden {
				continue
			}
			t.rows = append(t.rows, deepRow{n, d})
			if t.expanded[n] {
				rec(n.Children, d+1)
			}
		}
	}
	rec(t.data.Tree, 0)
	if t.cursor >= len(t.rows) {
		t.cursor = max(len(t.rows)-1, 0)
	}
}

func (t *deepTab) view(m *App, w, h int) string {
	th := m.theme
	inner := w - 2
	treeH := max((h-4)*3/5, 4)
	hexH := max(h-4-treeH, 3)
	t.scroll.height = treeH
	if t.cursor < t.scroll.offset {
		t.scroll.offset = t.cursor
	}
	if t.cursor >= t.scroll.offset+treeH {
		t.scroll.offset = t.cursor - treeH + 1
	}
	t.scroll.clamp(len(t.rows))
	var body []string
	for i := t.scroll.offset; i < len(t.rows) && len(body) < treeH; i++ {
		r := t.rows[i]
		mark := "  "
		if len(r.n.Children) > 0 {
			mark = "▶ "
			if t.expanded[r.n] {
				mark = "▼ "
			}
		}
		line := strings.Repeat("  ", r.depth) + mark + r.n.Label
		st := lipgloss.NewStyle().Foreground(th.Text)
		if r.n.Generated {
			st = st.Foreground(th.Generated)
		}
		if i == t.cursor {
			st = st.Background(th.SelBG).Foreground(th.SelFG)
		}
		body = append(body, st.Render(fit(line, inner)))
	}
	for len(body) < treeH {
		body = append(body, "")
	}
	body = append(body, lipgloss.NewStyle().Foreground(th.Border).Render(strings.Repeat("─", inner)))
	// hex dump with the selected range highlighted
	start, length := -1, 0
	if t.cursor < len(t.rows) {
		if o := t.rows[t.cursor].n.Offsets; len(o) >= 2 && t.rows[t.cursor].n.DS == 0 {
			start, length = o[0], o[1]
		}
	}
	data := t.data.Bytes
	firstLine := 0
	if start >= 0 {
		firstLine = start / 16
		if firstLine > len(data)/16-hexH+1 {
			firstLine = max(len(data)/16-hexH+1, 0)
		}
	}
	hl := lipgloss.NewStyle().Background(th.HexHLBG).Foreground(th.HexHLFG)
	for li := firstLine; len(body) < treeH+1+hexH && li*16 < len(data); li++ {
		var b strings.Builder
		fmt.Fprintf(&b, "%04x  ", li*16)
		var asc strings.Builder
		for i := 0; i < 16; i++ {
			p := li*16 + i
			if i == 8 {
				b.WriteByte(' ')
			}
			if p >= len(data) {
				b.WriteString("   ")
				continue
			}
			cell := fmt.Sprintf("%02x ", data[p])
			c := data[p]
			if c < 0x20 || c > 0x7e {
				c = '.'
			}
			if p >= start && p < start+length {
				cell = hl.Render(fmt.Sprintf("%02x", data[p])) + " "
				asc.WriteString(hl.Render(string(c)))
			} else {
				asc.WriteByte(c)
			}
			b.WriteString(cell)
		}
		body = append(body, fit(" "+b.String()+" "+asc.String(), inner))
	}
	for len(body) < h-2 {
		body = append(body, "")
	}
	return m.box("Deep dissection (Wireshark)", fmt.Sprintf("frame %d", t.frame), body, w, h, true)
}

func (t *deepTab) key(m *App, key string) (tea.Cmd, bool) {
	n := len(t.rows)
	var cur *deep.Node
	if t.cursor < n {
		cur = t.rows[t.cursor].n
	}
	switch key {
	case "up", "k":
		t.cursor = max(t.cursor-1, 0)
	case "down", "j":
		t.cursor = min(t.cursor+1, max(n-1, 0))
	case "pgup":
		t.cursor = max(t.cursor-t.scroll.height, 0)
	case "pgdown", "space":
		t.cursor = min(t.cursor+t.scroll.height, max(n-1, 0))
	case "home", "g":
		t.cursor = 0
	case "end", "G":
		t.cursor = max(n-1, 0)
	case "right", "l":
		if cur != nil && len(cur.Children) > 0 {
			t.expanded[cur] = true
			t.rebuild()
		}
	case "enter":
		if cur != nil && len(cur.Children) > 0 {
			t.expanded[cur] = !t.expanded[cur]
			t.rebuild()
		}
	case "left", "h":
		if cur != nil {
			if t.expanded[cur] {
				t.expanded[cur] = false
			} else {
				for i := t.cursor - 1; i >= 0; i-- {
					if t.rows[i].depth < t.rows[t.cursor].depth {
						t.cursor = i
						break
					}
				}
			}
			t.rebuild()
		}
	case "E":
		t.expanded = map[*deep.Node]bool{}
		t.rebuild()
	case "e":
		deep.Walk(t.data.Tree, func(n *deep.Node, _ int) bool { t.expanded[n] = true; return true })
		t.rebuild()
	case "a", "p":
		if cur != nil && cur.Filter != "" {
			m.tab = -1
			if key == "p" {
				m.fbar.set(cur.Filter)
				return m.focusFilter(), true
			}
			return m.applyFilter(cur.Filter), true
		}
	case "y":
		if cur != nil {
			return tea.SetClipboard(cur.Label), true
		}
	case "esc", "q":
		return m.closeTab(m.tab), true
	default:
		return nil, false
	}
	return nil, true
}

// ---- Wireshark taps ----

// deepTapDialog runs any Wireshark statistics tap and shows its result.
func (m *App) deepTapDialog() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	d := newInput("Wireshark Tap", "Tap name (conv:TCP, endpt:IPv4, srt:dns, rtd:…, eo:http, voip…):", "conv:TCP", func(m *App, v string) tea.Cmd {
		spec := strings.TrimSpace(v)
		c, err := m.ensureDeep()
		if err != nil {
			return m.setFlash(true, "%v", err)
		}
		raw, err := c.Tap(spec, "")
		if err != nil {
			return m.setFlash(true, "tap: %v", err)
		}
		var pretty bytes.Buffer
		if json.Indent(&pretty, raw, "", "  ") != nil {
			pretty.Write(raw)
		}
		return m.push(&textDialog{title: "Wireshark tap " + spec, lines: strings.Split(pretty.String(), "\n")})
	})
	d.help = []string{"Runs the statistics tap in Wireshark's engine and prints its JSON result."}
	return m.push(d)
}
