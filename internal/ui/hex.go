package ui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/poseydon/lazysniffer/internal/dissect"
)

type hexState struct {
	ds      int // data source shown
	cursor  int // byte offset
	offset  int // first visible line
	hlStart int
	hlLen   int
	bits    bool
	bodyH   int
	perLine int
}

// syncToNode shows the bytes of the selected tree item.
func (h *hexState) syncToNode(m *App) {
	n := m.details.current()
	if n == nil {
		h.hlStart, h.hlLen = 0, 0
		return
	}
	h.ds = int(n.DS)
	h.hlStart, h.hlLen = int(n.Start), int(n.Length)
	if h.hlLen > 0 {
		h.cursor = h.hlStart
		h.scrollTo(h.hlStart)
	}
}

func (h *hexState) scrollTo(off int) {
	if h.perLine == 0 || h.bodyH == 0 {
		return
	}
	line := off / h.perLine
	if line < h.offset || line >= h.offset+h.bodyH {
		h.offset = max(line-h.bodyH/3, 0)
	}
}

func (m *App) sourceData() []byte {
	if m.selPI == nil || m.bytes.ds >= len(m.selPI.Sources) {
		return nil
	}
	return m.selPI.Sources[m.bytes.ds].Data
}

func (m *App) renderBytes(w, h int, focused bool) string {
	hs := &m.bytes
	th := m.theme
	inner := w - 2
	data := m.sourceData()
	// Bytes per line: 16 when it fits, otherwise 8.
	per := 16
	if hs.bits {
		per = 4
		if inner >= 4+2+4*9+4+2 {
			per = 4
		}
	} else if inner < 6+16*3+1+16+2 {
		per = 8
	}
	hs.perLine = per
	bodyH := h - 2
	var tabs string
	if m.selPI != nil && len(m.selPI.Sources) > 1 {
		bodyH--
		var parts []string
		for i, s := range m.selPI.Sources {
			label := fmt.Sprintf("%s (%d bytes)", s.Name, len(s.Data))
			st := lipgloss.NewStyle().Foreground(th.Muted)
			if i == hs.ds {
				st = st.Foreground(th.Accent).Bold(true).Underline(true)
			}
			parts = append(parts, st.Render(label))
		}
		tabs = strings.Join(parts, "  ")
	}
	bodyH = max(bodyH, 1)
	hs.bodyH = bodyH
	lines := (len(data) + per - 1) / per
	hs.offset = max(min(hs.offset, lines-bodyH), 0)
	hl := lipgloss.NewStyle().Background(th.HexHLBG).Foreground(th.HexHLFG)
	cur := lipgloss.NewStyle().Reverse(true)
	dim := lipgloss.NewStyle().Foreground(th.HexDim)
	txt := lipgloss.NewStyle().Foreground(th.Text)
	var body []string
	for ln := hs.offset; ln < lines && len(body) < bodyH; ln++ {
		off := ln * per
		var b strings.Builder
		b.WriteString(dim.Render(fmt.Sprintf("%04x", off)))
		b.WriteString("  ")
		var asc strings.Builder
		for i := 0; i < per; i++ {
			p := off + i
			if hs.bits {
				if p < len(data) {
					cell := fmt.Sprintf("%08b", data[p])
					b.WriteString(m.byteStyle(p, hl, cur, focused, txt).Render(cell))
				} else {
					b.WriteString(strings.Repeat(" ", 8))
				}
				b.WriteString(" ")
			} else {
				if i == 8 {
					b.WriteString(" ")
				}
				if p < len(data) {
					b.WriteString(m.byteStyle(p, hl, cur, focused, txt).Render(fmt.Sprintf("%02x", data[p])))
				} else {
					b.WriteString("  ")
				}
				b.WriteString(" ")
			}
			if p < len(data) {
				c := data[p]
				ch := "."
				if c >= 0x20 && c < 0x7f {
					ch = string(rune(c))
				}
				st := m.byteStyle(p, hl, cur, focused, dim)
				if c >= 0x20 && c < 0x7f && !m.inHL(p) {
					st = m.byteStyle(p, hl, cur, focused, txt)
				}
				asc.WriteString(st.Render(ch))
			}
		}
		b.WriteString(" ")
		b.WriteString(asc.String())
		body = append(body, b.String())
	}
	if tabs != "" {
		body = append(make([]string, 0, len(body)+1), append([]string{tabs}, body...)...)
	}
	right := ""
	if len(data) > 0 {
		right = fmt.Sprintf("0x%04x", hs.cursor)
		if hs.hlLen > 0 {
			right = fmt.Sprintf("%d byte(s) at 0x%04x", hs.hlLen, hs.hlStart)
		}
	}
	return m.box("Bytes", right, body, w, h, focused)
}

func (m *App) inHL(p int) bool {
	return m.bytes.hlLen > 0 && p >= m.bytes.hlStart && p < m.bytes.hlStart+m.bytes.hlLen
}

func (m *App) byteStyle(p int, hl, cur lipgloss.Style, focused bool, base lipgloss.Style) lipgloss.Style {
	if focused && p == m.bytes.cursor {
		return cur
	}
	if m.inHL(p) {
		return hl
	}
	return base
}

func (m *App) hexKey(key string) (tea.Cmd, bool) {
	hs := &m.bytes
	data := m.sourceData()
	if len(data) == 0 {
		return nil, false
	}
	per := max(hs.perLine, 1)
	move := func(d int) {
		hs.cursor = max(min(hs.cursor+d, len(data)-1), 0)
		hs.scrollTo(hs.cursor)
		m.selectNodeAtByte(hs.ds, hs.cursor)
	}
	switch key {
	case "left", "h":
		move(-1)
	case "right", "l":
		move(1)
	case "up", "k":
		move(-per)
	case "down", "j":
		move(per)
	case "pgup":
		move(-per * max(hs.bodyH-1, 1))
	case "pgdown":
		move(per * max(hs.bodyH-1, 1))
	case "home", "g":
		move(-len(data))
	case "end", "G":
		move(len(data))
	case "enter":
		m.setFocus(paneDetails)
	default:
		return nil, false
	}
	return nil, true
}

// selectNodeAtByte selects the most specific tree item covering a byte, as
// clicking in Wireshark's bytes pane does.
func (m *App) selectNodeAtByte(ds, off int) {
	if m.selPI == nil {
		return
	}
	var best *dissect.Node
	m.selPI.Tree.Root.Walk(func(n *dissect.Node, _ int) bool {
		if n.Flags&dissect.NodeHidden != 0 || int(n.DS) != ds || n.Length <= 0 {
			return true
		}
		if off >= int(n.Start) && off < int(n.Start+n.Length) {
			if best == nil || n.Length <= best.Length {
				best = n
			}
		}
		return true
	})
	if best == nil {
		return
	}
	t := &m.details
	// Expand ancestors so the item is visible.
	for p := best.Parent; p != nil && p.Parent != nil; p = p.Parent {
		t.expanded[nodeKey(p)] = true
	}
	t.rebuild()
	for i, it := range t.items {
		if it.n == best {
			t.cursor = i
			t.selKey = nodeKey(best)
			break
		}
	}
	m.bytes.hlStart, m.bytes.hlLen = int(best.Start), int(best.Length)
}

func (m *App) toggleBits() tea.Cmd {
	m.bytes.bits = !m.bytes.bits
	return nil
}

func (m *App) nextDataSource() tea.Cmd {
	if m.selPI == nil || len(m.selPI.Sources) < 2 {
		return m.setFlash(true, "This packet has a single data source")
	}
	m.bytes.ds = (m.bytes.ds + 1) % len(m.selPI.Sources)
	m.bytes.cursor, m.bytes.offset, m.bytes.hlLen = 0, 0, 0
	return nil
}
