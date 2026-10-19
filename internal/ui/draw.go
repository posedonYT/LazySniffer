package ui

import (
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// rect is a screen region used for mouse hit-testing.
type rect struct{ x, y, w, h int }

func (r rect) contains(x, y int) bool {
	return x >= r.x && x < r.x+r.w && y >= r.y && y < r.y+r.h
}

// fit truncates or pads s (which may contain ANSI styles) to exactly w cells.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	sw := ansi.StringWidth(s)
	if sw > w {
		return ansi.Truncate(s, w, "…")
	}
	return s + strings.Repeat(" ", w-sw)
}

// fitRight right-aligns s within w cells.
func fitRight(s string, w int) string {
	sw := ansi.StringWidth(s)
	if sw >= w {
		return ansi.Truncate(s, w, "…")
	}
	return strings.Repeat(" ", w-sw) + s
}

// cut returns s without its first skip display cells (for horizontal scroll).
func cut(s string, skip int) string {
	if skip <= 0 {
		return s
	}
	return ansi.TruncateLeft(s, skip, "")
}

// box draws a bordered pane with a title and exactly h lines of height.
func (m *App) box(title, right string, body []string, w, h int, focused bool) string {
	if w < 4 || h < 2 {
		return ""
	}
	bc := m.theme.Border
	if focused {
		bc = m.theme.BorderFocus
	}
	bs := lipgloss.NewStyle().Foreground(bc)
	ts := lipgloss.NewStyle().Foreground(m.theme.Text).Bold(focused)
	if focused {
		ts = ts.Foreground(m.theme.BorderFocus)
	}
	inner := w - 2
	var b strings.Builder
	// Top border: ┌ Title ─────── right ┐
	t := ""
	if title != "" {
		t = " " + title + " "
	}
	rt := ""
	if right != "" {
		rt = " " + right + " "
	}
	maxT := max(inner-ansi.StringWidth(rt)-1, 0)
	if ansi.StringWidth(t) > maxT {
		t = ansi.Truncate(t, maxT, "…")
	}
	fill := max(inner-1-ansi.StringWidth(t)-ansi.StringWidth(rt), 0)
	b.WriteString(bs.Render("╭─"))
	b.WriteString(ts.Render(t))
	b.WriteString(bs.Render(strings.Repeat("─", fill)))
	b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Muted).Render(rt))
	b.WriteString(bs.Render("╮"))
	side := bs.Render("│")
	for i := 0; i < h-2; i++ {
		b.WriteByte('\n')
		line := ""
		if i < len(body) {
			line = body[i]
		}
		b.WriteString(side)
		b.WriteString(fit(line, inner))
		b.WriteString(side)
	}
	b.WriteByte('\n')
	b.WriteString(bs.Render("╰" + strings.Repeat("─", inner) + "╯"))
	return b.String()
}

// joinH places blocks side by side (each block is a multi-line string).
func joinH(blocks ...string) string { return lipgloss.JoinHorizontal(lipgloss.Top, blocks...) }

// joinV stacks blocks.
func joinV(blocks ...string) string {
	var nonEmpty []string
	for _, b := range blocks {
		if b != "" {
			nonEmpty = append(nonEmpty, b)
		}
	}
	return strings.Join(nonEmpty, "\n")
}

// keyHint renders "k label" pairs for the hints bar.
func (m *App) keyHint(k, label string) string {
	return lipgloss.NewStyle().Foreground(m.theme.Key).Bold(true).Render(k) + " " +
		lipgloss.NewStyle().Foreground(m.theme.Muted).Render(label)
}
