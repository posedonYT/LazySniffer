package ui

import (
	"image/color"

	"charm.land/lipgloss/v2"
	"github.com/lucasb-eyer/go-colorful"

	"github.com/poseydon/lazysniffer/internal/config"
	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/dissect"
)

type colorRule struct {
	config.ColorRule
	filter *dfilter.Filter
	bg, fg color.Color
}

// textColor is used in "foreground" coloring style: the rule's background
// hue, darkened or lightened to be readable as text.
func (r colorRule) textColor(dark bool) color.Color {
	c, err := colorful.Hex(r.BG)
	if err != nil {
		return r.fg
	}
	h, s, l := c.Hsl()
	// Very light backgrounds carry little hue; use the foreground instead.
	if s < 0.15 {
		fc, err := colorful.Hex(r.FG)
		if err == nil {
			h, s, _ = fc.Hsl()
		}
	}
	if dark {
		l = 0.72
	} else {
		l = 0.38
	}
	s = max(s, 0.55)
	return lipgloss.Color(colorful.Hsl(h, s, l).Hex())
}

func (m *App) loadColorRules() {
	rules, err := config.LoadColorRules()
	if err != nil {
		m.setFlash(true, "Coloring rules: %v", err)
	}
	m.colorRules = nil
	for _, r := range rules {
		if r.Disabled {
			continue
		}
		f, err := dfilter.Compile(r.Filter)
		if err != nil {
			// The rule uses a protocol lazysniffer does not dissect yet.
			continue
		}
		m.colorRules = append(m.colorRules, colorRule{ColorRule: r, filter: f,
			bg: lipgloss.Color(r.BG), fg: lipgloss.Color(r.FG)})
	}
}

// colorIndex returns the first matching coloring rule for a frame.
func (m *App) colorIndex(pi *dissect.PacketInfo) int {
	for i, r := range m.colorRules {
		if r.filter.Match(pi) {
			return i
		}
	}
	return -1
}

// resolveAddr renders Source/Destination columns.
func (m *App) resolveAddr(a dissect.Address) string {
	switch a.Type {
	case dissect.AddrEther:
		if m.cfg.ResolveMAC && etherName != nil {
			if s := etherName(a.Bytes()); s != "" {
				return s
			}
		}
	case dissect.AddrIPv4, dissect.AddrIPv6:
		if m.cfg.ResolveNetwork {
			if s := hostOf(a); s != "" {
				return s
			}
		}
	}
	return a.String()
}

// etherName is set by the resolver hooks (OUI vendor names).
var etherName func([]byte) string
