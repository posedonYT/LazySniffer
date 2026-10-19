package ui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// tabView is an analysis view shown as a tab next to the packet list
// (Follow Stream, Expert Info, statistics…).
type tabView interface {
	title() string
	view(m *App, w, h int) string
	key(m *App, key string) (tea.Cmd, bool)
	hints() [][2]string
	closed(m *App) tea.Cmd
}

// openTab adds a tab and switches to it.
func (m *App) openTab(t tabView) {
	m.tabs = append(m.tabs, t)
	m.tab = len(m.tabs) - 1
}

func (m *App) closeTab(i int) tea.Cmd {
	if i < 0 || i >= len(m.tabs) {
		return nil
	}
	t := m.tabs[i]
	m.tabs = append(m.tabs[:i], m.tabs[i+1:]...)
	if m.tab >= len(m.tabs) {
		m.tab = len(m.tabs) - 1
	}
	return t.closed(m)
}

func (m *App) currentTab() tabView {
	if m.tab < 0 || m.tab >= len(m.tabs) {
		return nil
	}
	return m.tabs[m.tab]
}

// tabKey handles tab switching keys; it reports whether key was used.
func (m *App) tabKey(key string) (tea.Cmd, bool) {
	if len(m.tabs) == 0 {
		return nil, false
	}
	switch key {
	case "]":
		m.tab++
		if m.tab >= len(m.tabs) {
			m.tab = -1
		}
		return nil, true
	case "[":
		m.tab--
		if m.tab < -1 {
			m.tab = len(m.tabs) - 1
		}
		return nil, true
	case "x":
		if m.tab >= 0 {
			return m.closeTab(m.tab), true
		}
	}
	if len(key) == 1 && key[0] >= '1' && key[0] <= '9' {
		i := int(key[0]-'1') - 1
		if i < len(m.tabs) {
			m.tab = i
			return nil, true
		}
	}
	return nil, false
}

func (m *App) renderTabBar() string {
	if len(m.tabs) == 0 {
		return ""
	}
	th := m.theme
	base := lipgloss.NewStyle().Background(th.BarBG).Foreground(th.Muted)
	sel := lipgloss.NewStyle().Background(th.SelBG).Foreground(th.SelFG).Bold(true)
	names := []string{"Packets"}
	for _, t := range m.tabs {
		names = append(names, t.title())
	}
	m.tabX = m.tabX[:0]
	var b strings.Builder
	x := 0
	for i, n := range names {
		label := fmt.Sprintf(" %d %s ", i+1, n)
		if i > 0 {
			label = fmt.Sprintf(" %d %s × ", i+1, n)
		}
		m.tabX = append(m.tabX, x)
		if i-1 == m.tab {
			b.WriteString(sel.Render(label))
		} else {
			b.WriteString(base.Render(label))
		}
		b.WriteString(base.Render("│"))
		x += ansi.StringWidth(label) + 1
	}
	right := base.Render(" [ ] switch · x close ")
	line := b.String()
	if gap := m.w - ansi.StringWidth(line) - ansi.StringWidth(right); gap > 0 {
		line += base.Render(strings.Repeat(" ", gap)) + right
	}
	return fit(line, m.w)
}

func (m *App) clickTabBar(x int) {
	for i := len(m.tabX) - 1; i >= 0; i-- {
		if x >= m.tabX[i] {
			m.tab = i - 1
			return
		}
	}
}

// scroller is shared scrolling logic for text-like tab views.
type scroller struct {
	offset int
	height int
}

func (s *scroller) key(key string, total int) bool {
	page := max(s.height-1, 1)
	switch key {
	case "up", "k":
		s.offset--
	case "down", "j":
		s.offset++
	case "pgup", "ctrl+b":
		s.offset -= page
	case "pgdown", "space", "ctrl+f":
		s.offset += page
	case "ctrl+u":
		s.offset -= page / 2
	case "ctrl+d":
		s.offset += page / 2
	case "home", "g":
		s.offset = 0
	case "end", "G":
		s.offset = total
	default:
		return false
	}
	s.clamp(total)
	return true
}

func (s *scroller) clamp(total int) {
	s.offset = max(min(s.offset, total-s.height), 0)
}
