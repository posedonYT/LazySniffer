package ui

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/follow"
)

var followModes = []string{"ASCII", "Hex Dump", "C Arrays", "Raw", "YAML", "UTF-8"}
var followDirs = []string{"Entire conversation", "Client → Server only", "Server → Client only"}

type followLine struct {
	text   string
	server bool
	frame  uint32
	note   bool // gap marker or header
}

type followTab struct {
	st         *follow.Stream
	mode       int
	dir        int
	lines      []followLine
	builtFor   [3]int
	scroll     scroller
	search     string
	prevFilter string
}

func (f *followTab) title() string {
	return fmt.Sprintf("Follow %s %d", f.st.Kind, f.st.Index)
}

func (f *followTab) hints() [][2]string {
	return [][2]string{{"↑↓", "scroll"}, {"m", "mode: " + followModes[f.mode]}, {"d", "direction"}, {"t", "TCP/TLS/HTTP"}, {"/", "search"},
		{"+/-", "next/prev stream"}, {"enter", "go to packet"}, {"s", "save"}, {"F", "filter out"}, {"y", "copy"}, {"esc", "back"}}
}

func (f *followTab) closed(m *App) tea.Cmd {
	// "Back": restore the display filter that was active before following.
	if m.filter != nil && m.filter.Text == f.st.Kind.Filter(f.st.Index) {
		return m.applyFilter(f.prevFilter)
	}
	return nil
}

// followSelected opens Follow Stream for the selected packet.
func (m *App) followSelected(kind int) tea.Cmd {
	if m.selPI == nil {
		return m.setFlash(true, "Select a packet first")
	}
	pi := m.selPI
	var k follow.Kind
	switch {
	case pi.Conv != nil && pi.Conv.Type == dissect.ConvTCP && kind != 2:
		k = follow.TCP
		switch kind {
		case 3:
			k = follow.TLS
		case 4:
			k = follow.HTTP
		}
	case pi.Conv != nil && pi.Conv.Type == dissect.ConvUDP && kind != 1:
		k = follow.UDP
	default:
		return m.setFlash(true, "The selected packet is not part of a TCP or UDP stream")
	}
	return m.openFollow(k, pi.Conv.Index, m.fbar.text())
}

func (m *App) openFollow(k follow.Kind, index uint32, prevFilter string) tea.Cmd {
	st, err := follow.Build(context.Background(), m.cap, k, index)
	if err != nil {
		return m.setFlash(true, "Follow: %v", err)
	}
	if len(st.Frames) == 0 {
		return m.setFlash(true, "%s stream %d does not exist", k, index)
	}
	m.openTab(&followTab{st: st, prevFilter: prevFilter})
	return m.applyFilter(k.Filter(index))
}

func (f *followTab) build(width int) {
	key := [3]int{f.mode, f.dir, width}
	if key == f.builtFor && f.lines != nil {
		return
	}
	f.builtFor = key
	f.lines = f.lines[:0]
	st := f.st
	include := func(c follow.Chunk) bool {
		return f.dir == 0 || (f.dir == 1 && !c.FromServer) || (f.dir == 2 && c.FromServer)
	}
	add := func(text string, server bool, frame uint32) {
		for len([]rune(text)) > width && width > 10 {
			r := []rune(text)
			f.lines = append(f.lines, followLine{text: string(r[:width]), server: server, frame: frame})
			text = string(r[width:])
		}
		f.lines = append(f.lines, followLine{text: text, server: server, frame: frame})
	}
	note := func(text string, frame uint32) {
		f.lines = append(f.lines, followLine{text: text, note: true, frame: frame})
	}
	var offs [2]int
	idx := [2]int{}
	if f.mode == 4 {
		note("peers:", 0)
		note("  - peer: 0", 0)
		note("    host: "+st.Client, 0)
		note("  - peer: 1", 0)
		note("    host: "+st.Server, 0)
		note("packets:", 0)
	}
	for _, c := range st.Chunks {
		if !include(c) {
			continue
		}
		if c.Missing > 0 {
			note(fmt.Sprintf("[%d bytes missing in capture file]", c.Missing), c.Frame)
		}
		peer := 0
		if c.FromServer {
			peer = 1
		}
		switch f.mode {
		case 0, 5:
			text := string(c.Data)
			if f.mode == 0 {
				text = printableASCII(c.Data)
			} else if !utf8.ValidString(text) {
				text = strings.ToValidUTF8(text, "�")
			}
			text = strings.ReplaceAll(text, "\r\n", "\n")
			text = strings.ReplaceAll(text, "\t", "    ")
			parts := strings.Split(text, "\n")
			if len(parts) > 1 && parts[len(parts)-1] == "" {
				parts = parts[:len(parts)-1]
			}
			for _, p := range parts {
				add(strings.ReplaceAll(p, "\r", ""), c.FromServer, c.Frame)
			}
		case 1:
			indent := ""
			if c.FromServer {
				indent = "    "
			}
			for i := 0; i < len(c.Data); i += 16 {
				end := min(i+16, len(c.Data))
				var hexb strings.Builder
				for j := i; j < i+16; j++ {
					if j < end {
						fmt.Fprintf(&hexb, "%02x ", c.Data[j])
					} else {
						hexb.WriteString("   ")
					}
					if j == i+7 {
						hexb.WriteByte(' ')
					}
				}
				add(fmt.Sprintf("%s%08x  %s %s", indent, offs[peer]+i, hexb.String(), printableASCII(c.Data[i:end])), c.FromServer, c.Frame)
			}
			offs[peer] += len(c.Data)
		case 2:
			add(fmt.Sprintf("char peer%d_%d[] = { /* Packet %d */", peer, idx[peer], c.Frame), c.FromServer, c.Frame)
			for i := 0; i < len(c.Data); i += 8 {
				var b strings.Builder
				for j := i; j < min(i+8, len(c.Data)); j++ {
					fmt.Fprintf(&b, "0x%02x", c.Data[j])
					if j < len(c.Data)-1 {
						b.WriteString(", ")
					}
				}
				add(b.String(), c.FromServer, c.Frame)
			}
			add("};", c.FromServer, c.Frame)
		case 3:
			add(fmt.Sprintf("%x", c.Data), c.FromServer, c.Frame)
		case 4:
			note(fmt.Sprintf("  - packet: %d", c.Frame), c.Frame)
			note(fmt.Sprintf("    peer: %d", peer), c.Frame)
			note(fmt.Sprintf("    index: %d", idx[peer]), c.Frame)
			note(fmt.Sprintf("    timestamp: %s", dissect.FormatRelTime(c.TS)), c.Frame)
			note("    data: !!binary |", c.Frame)
			enc := base64.StdEncoding.EncodeToString(c.Data)
			for i := 0; i < len(enc); i += 76 {
				add("      "+enc[i:min(i+76, len(enc))], c.FromServer, c.Frame)
			}
		}
		idx[peer]++
	}
	if len(f.lines) == 0 {
		note("(no payload in this direction)", 0)
	}
}

func printableASCII(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			out[i] = c
		case c < 0x20 || c > 0x7e:
			out[i] = '.'
		default:
			out[i] = c
		}
	}
	return string(out)
}

func (f *followTab) view(m *App, w, h int) string {
	th := m.theme
	inner := w - 2
	f.build(inner)
	bodyH := max(h-4, 1)
	f.scroll.height = bodyH
	f.scroll.clamp(len(f.lines))
	client := lipgloss.NewStyle().Foreground(lipgloss.LightDark(th.Dark)(lipgloss.Color("#b31d28"), lipgloss.Color("#ff7b72")))
	server := lipgloss.NewStyle().Foreground(lipgloss.LightDark(th.Dark)(lipgloss.Color("#0550ae"), lipgloss.Color("#79c0ff")))
	noteSt := lipgloss.NewStyle().Foreground(th.Muted)
	hl := lipgloss.NewStyle().Background(th.WarnBG).Foreground(th.Warn)
	st := f.st
	head := noteSt.Render(fmt.Sprintf(" %s  ", st.Kind.Filter(st.Index))) +
		client.Render("client "+st.Client) + noteSt.Render(" ⇄ ") + server.Render("server "+st.Server)
	body := []string{fit(head, inner), ""}
	for i := f.scroll.offset; i < len(f.lines) && len(body) < bodyH+2; i++ {
		l := f.lines[i]
		s := noteSt
		switch {
		case l.note:
		case l.server:
			s = server
		default:
			s = client
		}
		text := l.text
		if f.search != "" && strings.Contains(strings.ToLower(text), strings.ToLower(f.search)) {
			body = append(body, hl.Render(fit(text, inner)))
			continue
		}
		body = append(body, s.Render(fit(text, inner)))
	}
	total := st.ClientBytes + st.ServerBytes
	foot := fmt.Sprintf("%s (%s bytes) │ client: %d pkts, %s bytes │ server: %d pkts, %s bytes │ %d turns │ %s",
		followDirs[f.dir], commas(total), st.ClientPkts, commas(st.ClientBytes), st.ServerPkts, commas(st.ServerBytes), st.Turns(), followModes[f.mode])
	for len(body) < h-3 {
		body = append(body, "")
	}
	body = append(body, noteSt.Render(fit(foot, inner)))
	right := ""
	if len(f.lines) > 0 {
		right = fmt.Sprintf("%d%%", min(100, (f.scroll.offset+bodyH)*100/max(len(f.lines), 1)))
	}
	return m.box(fmt.Sprintf("Follow %s Stream (%s)", st.Kind, st.Kind.Filter(st.Index)), right, body, w, h, true)
}

func (f *followTab) key(m *App, key string) (tea.Cmd, bool) {
	if f.scroll.key(key, len(f.lines)) {
		return nil, true
	}
	switch key {
	case "m":
		f.mode = (f.mode + 1) % len(followModes)
		f.scroll.offset = 0
	case "d":
		f.dir = (f.dir + 1) % len(followDirs)
		f.scroll.offset = 0
	case "t":
		// Cycle the view of a TCP stream: raw TCP → decrypted TLS → HTTP.
		if f.st.Kind == follow.UDP {
			return nil, true
		}
		next := map[follow.Kind]follow.Kind{follow.TCP: follow.TLS, follow.TLS: follow.HTTP, follow.HTTP: follow.TCP}[f.st.Kind]
		st, err := follow.Build(context.Background(), m.cap, next, f.st.Index)
		if err != nil {
			return m.setFlash(true, "%v", err), true
		}
		f.st, f.lines, f.scroll.offset = st, nil, 0
		if next == follow.TLS && len(st.Chunks) == 0 {
			return m.setFlash(true, "No decrypted TLS data in this stream (Edit → TLS Key Log File)"), true
		}
	case "+", "=", "-":
		next := int(f.st.Index) + 1
		if key == "-" {
			next = int(f.st.Index) - 1
		}
		if next < 0 {
			return m.setFlash(true, "This is the first stream"), true
		}
		st, err := follow.Build(context.Background(), m.cap, f.st.Kind, uint32(next))
		if err != nil || len(st.Frames) == 0 {
			return m.setFlash(true, "No %s stream %d", f.st.Kind, next), true
		}
		f.st, f.lines, f.scroll.offset = st, nil, 0
		return m.applyFilter(st.Kind.Filter(st.Index)), true
	case "/":
		return m.push(newInput("Find in Stream", "Text:", f.search, func(m *App, v string) tea.Cmd {
			f.search = v
			return f.findNext(m, 1)
		})), true
	case "n":
		return f.findNext(m, 1), true
	case "N":
		return f.findNext(m, -1), true
	case "enter":
		for i := f.scroll.offset; i < len(f.lines); i++ {
			if fr := f.lines[i].frame; fr != 0 {
				m.tab = -1
				return m.gotoFrame(fr), true
			}
		}
	case "F":
		filter := "!(" + f.st.Kind.Filter(f.st.Index) + ")"
		if f.prevFilter != "" {
			filter = "(" + f.prevFilter + ") && " + filter
		}
		f.prevFilter = filter
		return m.closeTab(m.tab), true
	case "s":
		return f.saveDialog(m), true
	case "y":
		var b strings.Builder
		for _, l := range f.lines {
			b.WriteString(l.text + "\n")
		}
		return m.copyText("stream text", b.String()), true
	case "esc", "b", "q":
		return m.closeTab(m.tab), true
	default:
		return nil, false
	}
	return nil, true
}

func (f *followTab) findNext(m *App, dir int) tea.Cmd {
	if f.search == "" {
		return nil
	}
	n := len(f.lines)
	q := strings.ToLower(f.search)
	for i := 1; i <= n; i++ {
		idx := ((f.scroll.offset+dir*i)%n + n) % n
		if strings.Contains(strings.ToLower(f.lines[idx].text), q) {
			f.scroll.offset = idx
			f.scroll.clamp(n)
			return nil
		}
	}
	return m.setFlash(true, "%q not found in this stream", f.search)
}

func (f *followTab) saveDialog(m *App) tea.Cmd {
	def := fmt.Sprintf("%s-stream-%d.%s", strings.ToLower(f.st.Kind.String()), f.st.Index, map[int]string{0: "bin", 5: "txt", 1: "txt", 2: "c", 3: "hex", 4: "yaml"}[f.mode])
	d := newInput("Save Stream", "File (ASCII/UTF-8 save the raw bytes; other modes save the shown text):", def, func(m *App, v string) tea.Cmd {
		path := expandHome(strings.TrimSpace(v))
		var data []byte
		if f.mode == 0 || f.mode == 5 {
			for _, c := range f.st.Chunks {
				if f.dir == 0 || (f.dir == 1 && !c.FromServer) || (f.dir == 2 && c.FromServer) {
					data = append(data, c.Data...)
				}
			}
		} else {
			var b strings.Builder
			for _, l := range f.lines {
				b.WriteString(l.text + "\n")
			}
			data = []byte(b.String())
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return m.setFlash(true, "%v", err)
		}
		return m.setFlash(false, "Saved %s bytes to %s", commas(len(data)), path)
	})
	d.complete = completePath
	return m.push(d)
}
