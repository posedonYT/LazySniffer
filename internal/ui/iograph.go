package ui

import (
	"context"
	"fmt"
	"image/color"
	"math"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/stats"
)

var ioIntervals = []int64{1e6, 1e7, 1e8, 1e9, 1e10, 6e10, 6e11}
var ioIntervalNames = []string{"1 ms", "10 ms", "100 ms", "1 sec", "10 sec", "1 min", "10 min"}

var ioPalette = []color.Color{
	lipgloss.Color("#4ea1ff"), lipgloss.Color("#ff6b6b"), lipgloss.Color("#51cf66"),
	lipgloss.Color("#ffd43b"), lipgloss.Color("#cc5de8"), lipgloss.Color("#22b8cf"),
}

type ioGraphTab struct {
	series   []stats.IOSeries
	hidden   map[int]bool
	sel      int
	interval int // index into ioIntervals
	res      *stats.IOResult
	cursor   int
	log      bool
	perSec   bool
	err      string
}

func (g *ioGraphTab) title() string { return "I/O Graph" }

func (g *ioGraphTab) closed(*App) tea.Cmd { return nil }

func (g *ioGraphTab) hints() [][2]string {
	return [][2]string{{"←→", "move (shift ×10)"}, {"enter", "go to packet"}, {"i/I", "interval"}, {"tab", "series"}, {"n", "new"}, {"e", "edit"}, {"d", "delete"},
		{"v", "show/hide"}, {"o", "log scale"}, {"u", "per second"}, {"esc", "back"}}
}

func (m *App) openIOGraph() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	for i, t := range m.tabs {
		if _, ok := t.(*ioGraphTab); ok {
			m.tab = i
			return nil
		}
	}
	g := &ioGraphTab{hidden: map[int]bool{}, interval: 3,
		series: []stats.IOSeries{{Name: "All packets", Metric: stats.Packets}}}
	if f := m.fbar.text(); f != "" && m.filter != nil && !m.filter.Empty() {
		g.series = append(g.series, stats.IOSeries{Name: "Displayed", Filter: f, Metric: stats.Packets})
	} else {
		g.series = append(g.series, stats.IOSeries{Name: "TCP problems", Filter: "tcp.analysis.flags && !tcp.analysis.window_update", Metric: stats.Packets})
	}
	// Choose an interval that gives a readable chart.
	if n := m.cap.Count(); n > 1 {
		span := m.cap.Frame(uint32(n)).TS - m.cap.Frame(1).TS
		for i, iv := range ioIntervals {
			if span/iv <= 400 {
				g.interval = i
				break
			}
			g.interval = len(ioIntervals) - 1
		}
	}
	g.recompute(m)
	m.openTab(g)
	return nil
}

func (g *ioGraphTab) recompute(m *App) {
	res, err := stats.IO(context.Background(), m.cap, g.series, ioIntervals[g.interval])
	if err != nil {
		g.err = err.Error()
		return
	}
	g.err = ""
	g.res = res
	if g.cursor >= res.Bins {
		g.cursor = max(res.Bins-1, 0)
	}
}

func (g *ioGraphTab) unit(s stats.IOSeries) string {
	u := map[stats.Metric]string{stats.Packets: "packets", stats.Bytes: "bytes", stats.Bits: "bits"}[s.Metric]
	if u == "" {
		return s.Metric.String()[:strings.IndexByte(s.Metric.String(), '(')] + " " + s.Field
	}
	if g.perSec {
		return u + "/s"
	}
	return u
}

func (g *ioGraphTab) value(i, bin int) float64 {
	v := g.res.Series[i][bin]
	s := g.series[i]
	if g.perSec && s.Metric <= stats.Bits {
		v /= float64(g.res.Interval) / 1e9
	}
	return v
}

func (g *ioGraphTab) view(m *App, w, h int) string {
	th := m.theme
	inner := w - 2
	var body []string
	if g.err != "" {
		body = append(body, lipgloss.NewStyle().Foreground(th.Err).Render(" "+g.err))
	}
	// legend
	for i, s := range g.series {
		mark := "■"
		st := lipgloss.NewStyle().Foreground(ioPalette[i%len(ioPalette)])
		if g.hidden[i] {
			mark = "□"
		}
		cur := " "
		if i == g.sel {
			cur = "▸"
		}
		val := ""
		if g.res != nil && g.cursor < g.res.Bins && i < len(g.res.Series) {
			val = fmt.Sprintf("%s %s", fmtNum(g.value(i, g.cursor)), g.unit(s))
		}
		f := s.Filter
		if f == "" {
			f = "(all packets)"
		}
		body = append(body, fit(" "+cur+st.Render(mark)+" "+fit(s.Name, 16)+" "+fit(f, max(inner-48, 10))+" "+val, inner))
	}
	chartH := max(h-len(body)-6, 3)
	axisW := 9
	chartW := max(inner-axisW-4, 10)
	var ymax float64
	var cs []chartSeries
	if g.res != nil {
		for i := range g.series {
			if g.hidden[i] || i >= len(g.res.Series) {
				continue
			}
			vals := make([]float64, g.res.Bins)
			for b := range vals {
				vals[b] = g.value(i, b)
				ymax = math.Max(ymax, vals[b])
			}
			cs = append(cs, chartSeries{vals: vals, color: ioPalette[i%len(ioPalette)], bold: i == g.sel})
		}
	}
	if ymax == 0 {
		ymax = 1
	}
	rows := plot(chartW, chartH, cs, ymax, g.log)
	muted := lipgloss.NewStyle().Foreground(th.Muted)
	for y, r := range rows {
		label := ""
		switch y {
		case 0:
			label = fmtNum(ymax)
		case chartH / 2:
			if g.log {
				label = fmtNum(math.Pow(10, math.Log10(1+ymax)/2) - 1)
			} else {
				label = fmtNum(ymax / 2)
			}
		case chartH - 1:
			label = "0"
		}
		body = append(body, " "+muted.Render(fitRight(label, axisW))+" │"+r)
	}
	// x axis with the cursor marker
	if g.res != nil && g.res.Bins > 0 {
		axis := []rune(strings.Repeat("─", chartW))
		if g.res.Bins > 1 {
			cx := g.cursor * chartW / g.res.Bins
			axis[min(cx, chartW-1)] = '▲'
		}
		body = append(body, " "+strings.Repeat(" ", axisW)+" └"+muted.Render(string(axis)))
		span := float64(g.res.Bins) * float64(g.res.Interval) / 1e9
		left := "0"
		right := fmtSpan(span)
		mid := fmtSpan(span / 2)
		pad := chartW - len(left) - len(right) - len(mid)
		if pad > 2 {
			body = append(body, " "+strings.Repeat(" ", axisW+2)+muted.Render(left+strings.Repeat(" ", pad/2)+mid+strings.Repeat(" ", pad-pad/2)+right))
		}
		t := float64(g.cursor) * float64(g.res.Interval) / 1e9
		body = append(body, muted.Render(fmt.Sprintf(" interval %s%s · cursor at %s (bin %d of %d)", ioIntervalNames[g.interval],
			map[bool]string{true: " · log scale", false: ""}[g.log], fmtSpan(t), g.cursor+1, g.res.Bins)))
	}
	for len(body) < h-2 {
		body = append(body, "")
	}
	return m.box("I/O Graph", "", body, w, h, true)
}

func fmtNum(v float64) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.2fG", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.2fM", v/1e6)
	case v >= 1e4:
		return fmt.Sprintf("%.1fk", v/1e3)
	case v == math.Trunc(v):
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%.2f", v)
}

func (g *ioGraphTab) key(m *App, key string) (tea.Cmd, bool) {
	move := func(d int) {
		if g.res != nil {
			g.cursor = min(max(g.cursor+d, 0), max(g.res.Bins-1, 0))
		}
	}
	switch key {
	case "left", "h":
		move(-1)
	case "right", "l":
		move(1)
	case "shift+left", "H":
		move(-10)
	case "shift+right", "L":
		move(10)
	case "home", "g":
		g.cursor = 0
	case "end", "G":
		if g.res != nil {
			g.cursor = max(g.res.Bins-1, 0)
		}
	case "tab", "j", "down":
		g.sel = (g.sel + 1) % len(g.series)
	case "shift+tab", "k", "up":
		g.sel = (g.sel + len(g.series) - 1) % len(g.series)
	case "i":
		g.interval = min(g.interval+1, len(ioIntervals)-1)
		g.recompute(m)
	case "I":
		g.interval = max(g.interval-1, 0)
		g.recompute(m)
	case "o":
		g.log = !g.log
	case "u":
		g.perSec = !g.perSec
	case "v":
		g.hidden[g.sel] = !g.hidden[g.sel]
	case "d":
		if len(g.series) > 1 {
			g.series = append(g.series[:g.sel], g.series[g.sel+1:]...)
			g.sel = min(g.sel, len(g.series)-1)
			g.recompute(m)
		}
	case "n":
		return g.editSeries(m, -1), true
	case "e":
		return g.editSeries(m, g.sel), true
	case "enter":
		if g.res != nil && m.cap.Count() > 0 {
			target := g.res.StartTS + int64(g.cursor)*g.res.Interval
			n := m.cap.Count()
			i := sort.Search(n, func(i int) bool { return m.cap.Frame(uint32(i+1)).TS >= target })
			m.tab = -1
			return m.gotoFrame(uint32(min(i+1, n))), true
		}
	case "r":
		g.recompute(m)
	case "esc", "q":
		return m.closeTab(m.tab), true
	default:
		return nil, false
	}
	return nil, true
}

// editSeries asks for the filter, metric and field of a series (index -1
// adds a new one).
func (g *ioGraphTab) editSeries(m *App, idx int) tea.Cmd {
	var cur stats.IOSeries
	if idx >= 0 {
		cur = g.series[idx]
	}
	done := func(m *App, s stats.IOSeries) tea.Cmd {
		if s.Name == "" {
			s.Name = fmt.Sprintf("Graph %d", len(g.series)+1)
			if s.Filter != "" {
				s.Name = s.Filter
			}
		}
		if idx >= 0 {
			g.series[idx] = s
		} else {
			g.series = append(g.series, s)
			g.sel = len(g.series) - 1
		}
		g.recompute(m)
		return nil
	}
	return m.push(newInput("I/O Graph series", "Display filter (empty = all packets):", cur.Filter, func(m *App, filter string) tea.Cmd {
		filter = strings.TrimSpace(filter)
		var items []listItem
		for mt := stats.Metric(0); int(mt) < len(stats.MetricNames); mt++ {
			mt := mt
			items = append(items, listItem{label: mt.String(), run: func(m *App) tea.Cmd {
				s := stats.IOSeries{Filter: filter, Metric: mt, Name: cur.Name}
				if !mt.NeedsField() {
					return done(m, s)
				}
				return m.push(newInput("I/O Graph field", "Field to aggregate (e.g. tcp.analysis.ack_rtt, frame.len):", cur.Field, func(m *App, f string) tea.Cmd {
					f = strings.TrimSpace(f)
					if dissect.LookupField(f) == nil {
						return m.setFlash(true, "Unknown field %q", f)
					}
					s.Field = f
					if s.Name == "" || s.Name == cur.Name {
						s.Name = mt.String()[:strings.IndexByte(mt.String(), '(')] + "(" + f + ")"
					}
					return done(m, s)
				}))
			}})
		}
		return m.push(newList("Measure", items))
	}))
}

func fmtSpan(sec float64) string {
	switch {
	case sec < 1:
		return fmt.Sprintf("%.0f ms", sec*1e3)
	case sec < 120:
		return fmt.Sprintf("%.1f s", sec)
	case sec < 7200:
		return fmt.Sprintf("%.1f min", sec/60)
	}
	return fmt.Sprintf("%.1f h", sec/3600)
}
