package ui

import (
	"os"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

var logo = []string{
	"  _                          _  __  __           ",
	" | | __ _ _____   _ ___ _ __ (_)/ _|/ _| ___ _ __ ",
	" | |/ _` |_  / | | / __| '_ \\| | |_| |_ / _ \\ '__|",
	" | | (_| |/ /| |_| \\__ \\ | | | |  _|  _|  __/ |   ",
	" |_|\\__,_/___|\\__, |___/_| |_|_|_| |_|  \\___|_|   ",
	"              |___/                                ",
}

func (m *App) renderStart(w, h int) string {
	th := m.theme
	acc := lipgloss.NewStyle().Foreground(th.Accent).Bold(true)
	mut := lipgloss.NewStyle().Foreground(th.Muted)
	txt := lipgloss.NewStyle().Foreground(th.Text)
	var lines []string
	if w >= 60 && h >= 24 {
		for _, l := range logo {
			lines = append(lines, acc.Render(l))
		}
	} else {
		lines = append(lines, acc.Render("lazysniffer"))
	}
	lines = append(lines, mut.Render("terminal network protocol analyzer"), "")
	lines = append(lines, m.renderInterfaces(min(w-4, 110), m.capt.startFocus == 0)...)
	lines = append(lines, "")
	if len(m.cfg.RecentFiles) > 0 {
		title := "Recent files"
		if m.capt.startFocus == 1 {
			title = "▸ Recent files"
		}
		lines = append(lines, txt.Bold(true).Render(title))
		for i, p := range m.cfg.RecentFiles {
			if i >= max(h-len(lines)-6, 3) {
				break
			}
			size := "missing"
			if st, err := os.Stat(p); err == nil {
				size = humanBytes(st.Size())
			}
			label := shortenHome(p)
			row := fit(label, min(w-20, 70)) + "  " + size
			if i == m.startIdx && m.capt.startFocus == 1 {
				lines = append(lines, lipgloss.NewStyle().Background(th.SelBG).Foreground(th.SelFG).Render("▶ "+row))
			} else {
				lines = append(lines, txt.Render("  "+row))
			}
		}
	} else {
		lines = append(lines, mut.Render("No recent files yet. Press o to open one, or run: lazysniffer capture.pcapng"))
	}
	block := strings.Join(lines, "\n")
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, block)
}

func shortenHome(p string) string {
	if h, err := os.UserHomeDir(); err == nil && strings.HasPrefix(p, h) {
		return "~" + p[len(h):]
	}
	return p
}

func (m *App) startKey(key string) (tea.Cmd, bool) {
	if key == "tab" || key == "shift+tab" {
		if len(m.cfg.RecentFiles) > 0 {
			m.capt.startFocus = 1 - m.capt.startFocus
		}
		return nil, true
	}
	if m.capt.startFocus == 0 {
		return m.ifaceKey(key)
	}
	n := len(m.cfg.RecentFiles)
	switch key {
	case "up", "k":
		if n > 0 {
			m.startIdx = (m.startIdx - 1 + n) % n
		}
	case "down", "j":
		if n > 0 {
			m.startIdx = (m.startIdx + 1) % n
		}
	case "enter":
		if m.startIdx < n {
			return m.openFile(m.cfg.RecentFiles[m.startIdx]), true
		}
		return m.openFileDialog(), true
	default:
		return nil, false
	}
	return nil, true
}
