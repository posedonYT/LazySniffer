// Package ui is the Bubble Tea terminal interface of lazysniffer.
package ui

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

// Theme holds the colors and styles of the interface.
type Theme struct {
	Dark bool

	Text        color.Color
	Muted       color.Color
	Accent      color.Color
	Border      color.Color
	BorderFocus color.Color
	SelBG       color.Color
	SelFG       color.Color
	SelDimBG    color.Color
	BarBG       color.Color
	BarFG       color.Color
	MenuBG      color.Color
	MenuFG      color.Color
	MenuSelBG   color.Color
	MenuSelFG   color.Color
	Key         color.Color
	OK          color.Color
	OKBG        color.Color
	Err         color.Color
	ErrBG       color.Color
	Warn        color.Color
	WarnBG      color.Color
	HexHLBG     color.Color
	HexHLFG     color.Color
	HexDim      color.Color
	MarkedBG    color.Color
	MarkedFG    color.Color
	Generated   color.Color
	Link        color.Color
	Sev         [6]color.Color // by dissect.Severity
}

// NewTheme returns the dark or light theme.
func NewTheme(dark bool) *Theme {
	ld := lipgloss.LightDark(dark)
	c := lipgloss.Color
	t := &Theme{
		Dark:        dark,
		Text:        ld(c("#1f2328"), c("#d6dae0")),
		Muted:       ld(c("#6e7781"), c("#7d8590")),
		Accent:      ld(c("#0969da"), c("#58a6ff")),
		Border:      ld(c("#afb8c1"), c("#3d444d")),
		BorderFocus: ld(c("#0969da"), c("#58a6ff")),
		SelBG:       ld(c("#0969da"), c("#1f6feb")),
		SelFG:       c("#ffffff"),
		SelDimBG:    ld(c("#d0d7de"), c("#30363d")),
		BarBG:       ld(c("#eaeef2"), c("#161b22")),
		BarFG:       ld(c("#24292f"), c("#c9d1d9")),
		MenuBG:      ld(c("#f6f8fa"), c("#1c2128")),
		MenuFG:      ld(c("#24292f"), c("#c9d1d9")),
		MenuSelBG:   ld(c("#0969da"), c("#1f6feb")),
		MenuSelFG:   c("#ffffff"),
		Key:         ld(c("#8250df"), c("#d2a8ff")),
		OK:          ld(c("#1a7f37"), c("#3fb950")),
		OKBG:        ld(c("#dafbe1"), c("#12261e")),
		Err:         ld(c("#cf222e"), c("#f85149")),
		ErrBG:       ld(c("#ffebe9"), c("#3c1618")),
		Warn:        ld(c("#9a6700"), c("#d29922")),
		WarnBG:      ld(c("#fff8c5"), c("#33270c")),
		HexHLBG:     ld(c("#0969da"), c("#1f6feb")),
		HexHLFG:     c("#ffffff"),
		HexDim:      ld(c("#8c959f"), c("#6e7681")),
		MarkedBG:    ld(c("#000000"), c("#e6edf3")),
		MarkedFG:    ld(c("#ffffff"), c("#000000")),
		Generated:   ld(c("#6e7781"), c("#8b949e")),
		Link:        ld(c("#0969da"), c("#58a6ff")),
	}
	t.Sev = [6]color.Color{nil, t.Muted, t.Accent, t.Accent, t.Warn, t.Err}
	return t
}

func (t *Theme) style() lipgloss.Style { return lipgloss.NewStyle().Foreground(t.Text) }
