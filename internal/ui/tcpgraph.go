package ui

import (
	"context"
	"fmt"
	"math"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/stats"
)

var tcpGraphKinds = []string{"Time-Sequence (Stevens)", "Throughput", "Round Trip Time", "Window Scaling"}

type tcpGraphTab struct {
	data   *stats.TCPStream
	kind   int
	dir    int // 0: client→server data, 1: server→client data
	cursor int
}

func (g *tcpGraphTab) title() string { return fmt.Sprintf("TCP Graph %d", g.data.Index) }

func (g *tcpGraphTab) closed(*App) tea.Cmd { return nil }

func (g *tcpGraphTab) hints() [][2]string {
	return [][2]string{{"g/G", "graph type"}, {"d", "direction"}, {"←→", "move"}, {"enter", "go to packet"}, {"esc", "back"}}
}

func (m *App) openTCPGraph() tea.Cmd {
	if m.selPI == nil || m.selPI.Conv == nil || m.selPI.Conv.Type != dissect.ConvTCP {
		return m.setFlash(true, "Select a TCP packet first")
	}
	d, err := stats.TCPGraphData(context.Background(), m.cap, m.selPI.Conv.Index)
	if err != nil {
		return m.setFlash(true, "TCP graph: %v", err)
	}
	g := &tcpGraphTab{data: d}
	if len(d.Dir[1]) > 0 && len(d.Dir[0]) > 0 {
		// Follow the direction that carries more payload.
		var a, b float64
		for _, p := range d.Dir[0] {
			a += p.Len
		}
		for _, p := range d.Dir[1] {
			b += p.Len
		}
		if b > a {
			g.dir = 1
		}
	}
	m.openTab(g)
	return nil
}

const tcpGraphBins = 400

// series computes the plotted values for the current kind and direction.
func (g *tcpGraphTab) series() (vals []float64, label string, pts []stats.TCPPoint) {
	d := g.data
	src := d.Dir[g.dir]
	ack := d.Dir[1-g.dir]
	span := math.Max(d.Span, 1e-6)
	bins := make([]float64, tcpGraphBins)
	at := func(t float64) int { return min(int(t/span*float64(tcpGraphBins-1)), tcpGraphBins-1) }
	switch g.kind {
	case 0:
		label = "relative sequence number (bytes)"
		for _, p := range src {
			if p.Len > 0 {
				b := at(p.T)
				if p.NxtSeq > bins[b] {
					bins[b] = p.NxtSeq
				}
			}
		}
		// carry the last value forward so the curve is continuous
		for i := 1; i < len(bins); i++ {
			if bins[i] == 0 {
				bins[i] = bins[i-1]
			}
		}
	case 1:
		label = "throughput (bytes/s)"
		bw := span / tcpGraphBins
		for _, p := range src {
			b := at(p.T)
			bins[b] += p.Len / bw
		}
	case 2:
		label = "round trip time (ms)"
		for _, p := range ack {
			if p.RTT >= 0 {
				b := at(p.T)
				bins[b] = math.Max(bins[b], p.RTT*1e3)
			}
		}
	case 3:
		label = "window size / bytes in flight (bytes)"
		for _, p := range ack {
			b := at(p.T)
			bins[b] = math.Max(bins[b], p.Win)
		}
	}
	return bins, label, nil
}

func (g *tcpGraphTab) view(m *App, w, h int) string {
	th := m.theme
	inner := w - 2
	vals, label, _ := g.series()
	var cs []chartSeries
	cs = append(cs, chartSeries{vals: vals, color: ioPalette[0], bold: true})
	if g.kind == 3 {
		inflight := make([]float64, tcpGraphBins)
		span := math.Max(g.data.Span, 1e-6)
		for _, p := range g.data.Dir[g.dir] {
			if p.InFlight >= 0 {
				b := min(int(p.T/span*float64(tcpGraphBins-1)), tcpGraphBins-1)
				inflight[b] = math.Max(inflight[b], p.InFlight)
			}
		}
		cs = append(cs, chartSeries{vals: inflight, color: ioPalette[1]})
	}
	var ymax float64
	for _, s := range cs {
		for _, v := range s.vals {
			ymax = math.Max(ymax, v)
		}
	}
	if ymax == 0 {
		ymax = 1
	}
	axisW := 10
	chartW := max(inner-axisW-4, 10)
	chartH := max(h-8, 3)
	rows := plot(chartW, chartH, cs, ymax, false)
	muted := lipgloss.NewStyle().Foreground(th.Muted)
	dirName := map[int]string{0: g.data.Client + " → " + g.data.Server, 1: g.data.Server + " → " + g.data.Client}[g.dir]
	var body []string
	var tabs string
	for i, k := range tcpGraphKinds {
		st := muted
		if i == g.kind {
			st = lipgloss.NewStyle().Background(th.Accent).Foreground(th.SelFG).Bold(true)
		}
		tabs += st.Render(fmt.Sprintf(" %d %s ", i+1, k)) + " "
	}
	body = append(body, fit(tabs, inner), muted.Render(fit(" "+dirName+" · "+label, inner)))
	for y, r := range rows {
		l := ""
		switch y {
		case 0:
			l = fmtNum(ymax)
		case chartH / 2:
			l = fmtNum(ymax / 2)
		case chartH - 1:
			l = "0"
		}
		body = append(body, " "+muted.Render(fitRight(l, axisW))+" │"+r)
	}
	axis := repeatRune('─', chartW)
	cx := g.cursor * chartW / tcpGraphBins
	axis[min(cx, chartW-1)] = '▲'
	body = append(body, " "+fmt.Sprintf("%*s", axisW, "")+" └"+muted.Render(string(axis)))
	t := float64(g.cursor) / tcpGraphBins * g.data.Span
	cur := ""
	if g.cursor < len(vals) {
		cur = fmt.Sprintf("value %s", fmtNum(vals[g.cursor]))
	}
	body = append(body, muted.Render(fmt.Sprintf(" 0 – %s · cursor at %s · %s", fmtSpan(g.data.Span), fmtSpan(t), cur)))
	for len(body) < h-2 {
		body = append(body, "")
	}
	return m.box(fmt.Sprintf("TCP Stream Graph (tcp.stream eq %d)", g.data.Index), "", body, w, h, true)
}

func repeatRune(r rune, n int) []rune {
	out := make([]rune, n)
	for i := range out {
		out[i] = r
	}
	return out
}

func (g *tcpGraphTab) key(m *App, key string) (tea.Cmd, bool) {
	switch key {
	case "g":
		g.kind = (g.kind + 1) % len(tcpGraphKinds)
	case "G":
		g.kind = (g.kind + len(tcpGraphKinds) - 1) % len(tcpGraphKinds)
	case "d":
		g.dir = 1 - g.dir
	case "left", "h":
		g.cursor = max(g.cursor-1, 0)
	case "right", "l":
		g.cursor = min(g.cursor+1, tcpGraphBins-1)
	case "shift+left", "H":
		g.cursor = max(g.cursor-10, 0)
	case "shift+right", "L":
		g.cursor = min(g.cursor+10, tcpGraphBins-1)
	case "home":
		g.cursor = 0
	case "end":
		g.cursor = tcpGraphBins - 1
	case "enter":
		t := float64(g.cursor) / tcpGraphBins * g.data.Span
		best, bd := uint32(0), math.Inf(1)
		for _, p := range g.data.Dir[g.dir] {
			if d := math.Abs(p.T - t); d < bd {
				best, bd = p.Frame, d
			}
		}
		if best != 0 {
			m.tab = -1
			return m.gotoFrame(best), true
		}
	case "esc", "q":
		return m.closeTab(m.tab), true
	default:
		return nil, false
	}
	return nil, true
}
