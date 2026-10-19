package ui

import (
	tea "charm.land/bubbletea/v2"

	"github.com/poseydon/lazysniffer/internal/capture"
)

func (m *App) doctorDialog() tea.Cmd {
	var lines []string
	for _, c := range capture.Doctor() {
		mark := "✓"
		if !c.OK {
			mark = "✗"
		}
		lines = append(lines, mark+" "+fit(c.Name, 24)+" "+c.Info)
		if c.Fix != "" {
			lines = append(lines, "    → "+c.Fix)
		}
	}
	return m.showText("Capture Doctor", lines)
}
