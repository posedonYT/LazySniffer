package ui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/sahilm/fuzzy"
)

// ---- composition ----

func (m *App) overlays() []*lipgloss.Layer {
	var out []*lipgloss.Layer
	if l := m.suggestionLayer(); l != nil {
		out = append(out, l)
	}
	if m.menuOpen >= 0 {
		if l := m.menuLayer(); l != nil {
			out = append(out, l)
		}
	}
	if m.palette != nil {
		out = append(out, m.paletteLayer())
	}
	for i, d := range m.dialogs {
		s := d.view(m)
		w, h := lipgloss.Width(s), lipgloss.Height(s)
		x, y := max((m.w-w)/2, 0), max((m.h-h)/3, 1)
		out = append(out, lipgloss.NewLayer(s).X(x).Y(y).Z(20+i))
	}
	return out
}

// frame draws a popup box with a title.
func (m *App) frame(title string, lines []string, width int) string {
	th := m.theme
	bs := lipgloss.NewStyle().Foreground(th.BorderFocus).Background(th.MenuBG)
	ts := lipgloss.NewStyle().Foreground(th.Accent).Background(th.MenuBG).Bold(true)
	bg := lipgloss.NewStyle().Background(th.MenuBG).Foreground(th.MenuFG)
	inner := width - 2
	var b strings.Builder
	t := ""
	if title != "" {
		t = " " + title + " "
	}
	if ansi.StringWidth(t) > inner-1 {
		t = ansi.Truncate(t, inner-1, "…")
	}
	b.WriteString(bs.Render("╭─") + ts.Render(t) + bs.Render(strings.Repeat("─", max(inner-1-ansi.StringWidth(t), 0))+"╮"))
	for _, l := range lines {
		b.WriteString("\n" + bs.Render("│") + bg.Render(fit(l, inner)) + bs.Render("│"))
	}
	b.WriteString("\n" + bs.Render("╰"+strings.Repeat("─", inner)+"╯"))
	return b.String()
}

// ---- menu bar ----

func (m *App) renderMenuBar() string {
	th := m.theme
	st := lipgloss.NewStyle().Background(th.BarBG).Foreground(th.BarFG)
	sel := lipgloss.NewStyle().Background(th.MenuSelBG).Foreground(th.MenuSelFG)
	key := lipgloss.NewStyle().Background(th.BarBG).Foreground(th.Key).Bold(true)
	m.menuX = m.menuX[:0]
	var b strings.Builder
	x := 0
	b.WriteString(key.Render(" ◆ "))
	x += 3
	for i, name := range menuOrder {
		if len(m.menuActions(name)) == 0 {
			m.menuX = append(m.menuX, -1)
			continue
		}
		m.menuX = append(m.menuX, x)
		label := " " + name + " "
		if i == m.menuOpen {
			b.WriteString(sel.Render(label))
		} else {
			b.WriteString(st.Render(label))
		}
		x += ansi.StringWidth(label)
	}
	right := st.Foreground(th.Muted).Render("F10 menu · ctrl+p commands · ? help ")
	line := b.String()
	gap := m.w - ansi.StringWidth(line) - ansi.StringWidth(right)
	if gap > 0 {
		line += st.Render(strings.Repeat(" ", gap)) + right
	}
	m.rMenu = rect{0, 0, m.w, 1}
	return fit(line, m.w)
}

func (m *App) menuActions(menu string) []*Action {
	var out []*Action
	for _, a := range m.actions {
		if a.Menu == menu {
			out = append(out, a)
		}
	}
	return out
}

func (m *App) openMenuBar() tea.Cmd {
	m.openMenu(0)
	return nil
}

func (m *App) openMenu(i int) {
	n := len(menuOrder)
	for k := 0; k < n; k++ {
		j := ((i+k)%n + n) % n
		if items := m.menuActions(menuOrder[j]); len(items) > 0 {
			m.menuOpen, m.menuItems, m.menuIdx = j, items, 0
			for m.menuIdx < len(items) && !m.enabled(items[m.menuIdx]) {
				m.menuIdx++
			}
			return
		}
	}
}

func (m *App) menuKey(k tea.KeyPressMsg) tea.Cmd {
	n := len(m.menuItems)
	step := func(d int) {
		for i := 1; i <= n; i++ {
			j := ((m.menuIdx+d*i)%n + n) % n
			if m.enabled(m.menuItems[j]) {
				m.menuIdx = j
				return
			}
		}
	}
	switch k.String() {
	case "esc", "f10", "alt+m":
		m.menuOpen = -1
	case "left", "h":
		cur := m.menuOpen
		for j := 1; j <= len(menuOrder); j++ {
			c := ((cur-j)%len(menuOrder) + len(menuOrder)) % len(menuOrder)
			if len(m.menuActions(menuOrder[c])) > 0 {
				m.openMenu(c)
				break
			}
		}
	case "right", "l", "tab":
		m.openMenu(m.menuOpen + 1)
	case "up", "k":
		step(-1)
	case "down", "j":
		step(1)
	case "enter", "space":
		if m.menuIdx < n && m.enabled(m.menuItems[m.menuIdx]) {
			a := m.menuItems[m.menuIdx]
			m.menuOpen = -1
			return a.Run(m)
		}
	default:
		// First letter jumps to a menu (like Alt+F in GUIs).
		if t := k.Text; len(t) == 1 {
			for i, name := range menuOrder {
				if strings.EqualFold(name[:1], t) && len(m.menuActions(name)) > 0 {
					m.openMenu(i)
					break
				}
			}
		}
	}
	return nil
}

func (m *App) menuLayer() *lipgloss.Layer {
	th := m.theme
	items := m.menuItems
	width := 20
	for _, a := range items {
		width = max(width, ansi.StringWidth(a.Title)+ansi.StringWidth(keyLabel(a))+6)
	}
	var lines []string
	prevGroup := -1
	for i, a := range items {
		if prevGroup >= 0 && a.Group != prevGroup {
			lines = append(lines, lipgloss.NewStyle().Foreground(th.Border).Render(strings.Repeat("─", width-2)))
		}
		prevGroup = a.Group
		st := lipgloss.NewStyle().Foreground(th.MenuFG).Background(th.MenuBG)
		ks := st.Foreground(th.Key)
		if !m.enabled(a) {
			st = st.Foreground(th.Muted)
			ks = ks.Foreground(th.Muted)
		}
		if i == m.menuIdx {
			st = st.Background(th.MenuSelBG).Foreground(th.MenuSelFG)
			ks = ks.Background(th.MenuSelBG).Foreground(th.MenuSelFG)
		}
		kl := keyLabel(a)
		left := " " + a.Title
		gap := width - 2 - ansi.StringWidth(left) - ansi.StringWidth(kl) - 1
		lines = append(lines, st.Render(left+strings.Repeat(" ", max(gap, 1)))+ks.Render(kl+" "))
	}
	box := m.frame("", lines, width)
	x := 0
	if m.menuOpen < len(m.menuX) && m.menuX[m.menuOpen] >= 0 {
		x = m.menuX[m.menuOpen]
	}
	x = min(x, max(m.w-width, 0))
	return lipgloss.NewLayer(box).X(x).Y(1).Z(10)
}

// ---- command palette ----

type paletteState struct {
	edit    lineEdit
	matches []*Action
	idx     int
}

func (m *App) openPalette() tea.Cmd {
	m.palette = &paletteState{}
	m.paletteFilter()
	return nil
}

func actionLabel(a *Action) string {
	if a.Menu != "" {
		return a.Menu + " › " + a.Title
	}
	return a.Title
}

func (m *App) paletteFilter() {
	p := m.palette
	var avail []*Action
	for _, a := range m.actions {
		if m.enabled(a) && a.ID != "help.palette" {
			avail = append(avail, a)
		}
	}
	q := p.edit.text()
	if q == "" {
		p.matches = avail
		p.idx = 0
		return
	}
	labels := make([]string, len(avail))
	for i, a := range avail {
		labels[i] = actionLabel(a)
	}
	res := fuzzy.Find(q, labels)
	p.matches = p.matches[:0]
	for _, r := range res {
		p.matches = append(p.matches, avail[r.Index])
	}
	p.idx = 0
}

func (m *App) paletteKey(k tea.KeyPressMsg) tea.Cmd {
	p := m.palette
	switch k.String() {
	case "esc", "ctrl+p", "ctrl+c":
		m.palette = nil
	case "enter":
		if p.idx < len(p.matches) {
			a := p.matches[p.idx]
			m.palette = nil
			return a.Run(m)
		}
	case "up", "ctrl+k":
		if len(p.matches) > 0 {
			p.idx = (p.idx - 1 + len(p.matches)) % len(p.matches)
		}
	case "down", "ctrl+j", "tab":
		if len(p.matches) > 0 {
			p.idx = (p.idx + 1) % len(p.matches)
		}
	default:
		if p.edit.edit(k) {
			m.paletteFilter()
		}
	}
	return nil
}

func (m *App) paletteLayer() *lipgloss.Layer {
	th := m.theme
	p := m.palette
	width := min(max(m.w*6/10, 50), m.w-4)
	inner := width - 2
	rows := min(14, m.h-8)
	in := lipgloss.NewStyle().Foreground(th.Text).Background(th.MenuBG)
	lines := []string{in.Render(" › ") + m.renderLineEdit(&p.edit, in, true)}
	lines = append(lines, lipgloss.NewStyle().Foreground(th.Border).Render(strings.Repeat("─", inner)))
	start := 0
	if p.idx >= rows {
		start = p.idx - rows + 1
	}
	for i := start; i < len(p.matches) && i < start+rows; i++ {
		a := p.matches[i]
		st := lipgloss.NewStyle().Foreground(th.MenuFG).Background(th.MenuBG)
		ks := st.Foreground(th.Key)
		if i == p.idx {
			st = st.Background(th.MenuSelBG).Foreground(th.MenuSelFG)
			ks = ks.Background(th.MenuSelBG).Foreground(th.MenuSelFG)
		}
		left := " " + actionLabel(a)
		kl := keyLabel(a)
		gap := inner - ansi.StringWidth(left) - ansi.StringWidth(kl) - 1
		lines = append(lines, st.Render(left+strings.Repeat(" ", max(gap, 1)))+ks.Render(kl+" "))
	}
	if len(p.matches) == 0 {
		lines = append(lines, lipgloss.NewStyle().Foreground(th.Muted).Render(" No matching commands"))
	}
	box := m.frame("Commands", lines, width)
	return lipgloss.NewLayer(box).X((m.w - width) / 2).Y(2).Z(15)
}

func (m *App) renderLineEdit(e *lineEdit, st lipgloss.Style, focused bool) string {
	var b strings.Builder
	cur := st.Reverse(true)
	for i, r := range e.buf {
		if focused && i == e.pos {
			b.WriteString(cur.Render(string(r)))
		} else {
			b.WriteString(st.Render(string(r)))
		}
	}
	if focused && e.pos >= len(e.buf) {
		b.WriteString(cur.Render(" "))
	}
	return b.String()
}

// ---- dialogs ----

type dialog interface {
	key(m *App, k tea.KeyPressMsg) tea.Cmd
	paste(m *App, s string) tea.Cmd
	view(m *App) string
}

func (m *App) push(d dialog) tea.Cmd {
	m.dialogs = append(m.dialogs, d)
	return nil
}

func (m *App) pop() {
	if len(m.dialogs) > 0 {
		m.dialogs = m.dialogs[:len(m.dialogs)-1]
	}
}

// listItem is an entry of a list dialog.
type listItem struct {
	label    string
	detail   string
	run      func(m *App) tea.Cmd
	disabled bool
	checked  *bool // shows a checkbox when non-nil
	keep     bool  // keep the dialog open after running
}

type listDialog struct {
	title  string
	items  []listItem
	edit   lineEdit
	match  []int
	idx    int
	width  int
	filter bool // typing filters items
	footer string
}

func newList(title string, items []listItem) *listDialog {
	d := &listDialog{title: title, items: items, filter: len(items) > 8}
	d.refilter()
	for d.idx < len(d.match) && d.items[d.match[d.idx]].disabled {
		d.idx++
	}
	return d
}

func (d *listDialog) refilter() {
	q := strings.ToLower(d.edit.text())
	d.match = d.match[:0]
	for i, it := range d.items {
		if q == "" || strings.Contains(strings.ToLower(it.label+" "+it.detail), q) {
			d.match = append(d.match, i)
		}
	}
	if d.idx >= len(d.match) {
		d.idx = max(len(d.match)-1, 0)
	}
}

func (d *listDialog) paste(m *App, s string) tea.Cmd {
	if d.filter {
		d.edit.insert(s)
		d.refilter()
	}
	return nil
}

func (d *listDialog) key(m *App, k tea.KeyPressMsg) tea.Cmd {
	n := len(d.match)
	switch k.String() {
	case "esc", "ctrl+c":
		m.pop()
	case "up", "ctrl+p", "k":
		if k.String() == "k" && d.filter {
			break
		}
		for i := 1; i <= n; i++ {
			j := (d.idx - i + n*2) % n
			if !d.items[d.match[j]].disabled {
				d.idx = j
				break
			}
		}
		return nil
	case "down", "ctrl+n", "j", "tab":
		if k.String() == "j" && d.filter {
			break
		}
		for i := 1; i <= n; i++ {
			j := (d.idx + i) % n
			if !d.items[d.match[j]].disabled {
				d.idx = j
				break
			}
		}
		return nil
	case "enter", "space":
		if k.String() == "space" && d.filter {
			break
		}
		if d.idx < n {
			it := d.items[d.match[d.idx]]
			if it.disabled || it.run == nil {
				return nil
			}
			if !it.keep {
				m.pop()
			}
			return it.run(m)
		}
		return nil
	default:
		if !d.filter {
			// Number keys pick items directly.
			if t := k.Text; len(t) == 1 && t[0] >= '1' && t[0] <= '9' {
				i := int(t[0] - '1')
				if i < n && !d.items[d.match[i]].disabled {
					d.idx = i
					it := d.items[d.match[i]]
					if !it.keep {
						m.pop()
					}
					if it.run != nil {
						return it.run(m)
					}
				}
			}
			return nil
		}
	}
	if d.filter && d.edit.edit(k) {
		d.refilter()
	}
	return nil
}

func (d *listDialog) view(m *App) string {
	th := m.theme
	width := d.width
	if width == 0 {
		width = ansi.StringWidth(d.title) + 6
		for _, it := range d.items {
			width = max(width, ansi.StringWidth(it.label)+ansi.StringWidth(it.detail)+10)
		}
	}
	width = min(max(width, 30), m.w-4)
	inner := width - 2
	var lines []string
	base := lipgloss.NewStyle().Foreground(th.MenuFG).Background(th.MenuBG)
	if d.filter {
		lines = append(lines, base.Foreground(th.Muted).Render(" Search: ")+m.renderLineEdit(&d.edit, base, true))
	}
	rows := min(len(d.match), max(m.h-10, 3))
	start := 0
	if d.idx >= rows {
		start = d.idx - rows + 1
	}
	for k := start; k < len(d.match) && k < start+rows; k++ {
		it := d.items[d.match[k]]
		st := base
		ds := base.Foreground(th.Muted)
		if it.disabled {
			st = st.Foreground(th.Muted)
		}
		if k == d.idx {
			st = st.Background(th.MenuSelBG).Foreground(th.MenuSelFG)
			ds = ds.Background(th.MenuSelBG).Foreground(th.MenuSelFG)
		}
		prefix := " "
		if !d.filter && k < 9 {
			prefix = lipgloss.NewStyle().Inherit(st).Foreground(th.Key).Render(string(rune('1'+k))) + st.Render(" ")
		}
		box := ""
		if it.checked != nil {
			box = "[ ] "
			if *it.checked {
				box = "[x] "
			}
		}
		left := st.Render(" ") + prefix + st.Render(box+it.label)
		right := ds.Render(it.detail + " ")
		gap := inner - ansi.StringWidth(left) - ansi.StringWidth(right)
		lines = append(lines, left+st.Render(strings.Repeat(" ", max(gap, 1)))+right)
	}
	if len(d.match) == 0 {
		lines = append(lines, base.Foreground(th.Muted).Render(" Nothing matches"))
	}
	if d.footer != "" {
		lines = append(lines, base.Foreground(th.Muted).Render(" "+d.footer))
	}
	return m.frame(d.title, lines, width)
}

// inputDialog asks for a line of text.
type inputDialog struct {
	title    string
	prompt   string
	help     []string
	edit     lineEdit
	err      string
	submit   func(m *App, v string) tea.Cmd
	validate func(v string) error
	complete func(v string) string
}

func newInput(title, prompt, value string, submit func(m *App, v string) tea.Cmd) *inputDialog {
	d := &inputDialog{title: title, prompt: prompt, submit: submit}
	d.edit.set(value)
	return d
}

func (d *inputDialog) paste(m *App, s string) tea.Cmd {
	d.edit.insert(strings.TrimSpace(s))
	d.check()
	return nil
}

func (d *inputDialog) check() {
	d.err = ""
	if d.validate != nil {
		if err := d.validate(d.edit.text()); err != nil {
			d.err = err.Error()
		}
	}
}

func (d *inputDialog) key(m *App, k tea.KeyPressMsg) tea.Cmd {
	switch k.String() {
	case "esc", "ctrl+c":
		m.pop()
		return nil
	case "enter":
		d.check()
		if d.err != "" {
			return nil
		}
		m.pop()
		return d.submit(m, d.edit.text())
	case "tab":
		if d.complete != nil {
			d.edit.set(d.complete(d.edit.text()))
			d.check()
		}
		return nil
	}
	if d.edit.edit(k) {
		d.check()
	}
	return nil
}

func (d *inputDialog) view(m *App) string {
	th := m.theme
	width := min(max(70, ansi.StringWidth(d.title)+8), m.w-4)
	base := lipgloss.NewStyle().Foreground(th.MenuFG).Background(th.MenuBG)
	var lines []string
	if d.prompt != "" {
		lines = append(lines, base.Render(" "+d.prompt))
	}
	field := lipgloss.NewStyle().Foreground(th.Text).Background(th.BarBG)
	lines = append(lines, base.Render(" ")+field.Render(fit(m.renderLineEdit(&d.edit, field, true), width-4))+base.Render(" "))
	if d.err != "" {
		lines = append(lines, base.Foreground(th.Err).Render(" "+d.err))
	}
	for _, h := range d.help {
		lines = append(lines, base.Foreground(th.Muted).Render(" "+h))
	}
	return m.frame(d.title, lines, width)
}

// textDialog shows scrollable text.
type textDialog struct {
	title  string
	lines  []string
	offset int
}

func (d *textDialog) paste(*App, string) tea.Cmd { return nil }

func (d *textDialog) key(m *App, k tea.KeyPressMsg) tea.Cmd {
	rows := max(m.h-8, 3)
	switch k.String() {
	case "esc", "q", "enter", "ctrl+c", "?":
		m.pop()
	case "up", "k":
		d.offset--
	case "down", "j":
		d.offset++
	case "pgup", "ctrl+b":
		d.offset -= rows
	case "pgdown", "space", "ctrl+f":
		d.offset += rows
	case "home", "g":
		d.offset = 0
	case "end", "G":
		d.offset = len(d.lines)
	}
	d.offset = max(min(d.offset, len(d.lines)-rows), 0)
	return nil
}

func (d *textDialog) view(m *App) string {
	width := 40
	for _, l := range d.lines {
		width = max(width, ansi.StringWidth(l)+4)
	}
	width = min(width, m.w-4)
	rows := max(m.h-8, 3)
	end := min(d.offset+rows, len(d.lines))
	shown := make([]string, 0, rows+1)
	for _, l := range d.lines[d.offset:end] {
		shown = append(shown, " "+l)
	}
	if len(d.lines) > rows {
		shown = append(shown, lipgloss.NewStyle().Foreground(m.theme.Muted).Render(
			strings.Repeat(" ", max(width-30, 0))+"↑↓ scroll · esc close"))
	}
	return m.frame(d.title, shown, width)
}

func (m *App) showText(title string, lines []string) tea.Cmd {
	return m.push(&textDialog{title: title, lines: lines})
}

// confirm asks a yes/no question.
func (m *App) confirm(title, question string, yes func(m *App) tea.Cmd) tea.Cmd {
	d := newList(title, []listItem{
		{label: "Yes", run: yes},
		{label: "No", run: func(*App) tea.Cmd { return nil }},
	})
	d.footer = question
	return m.push(d)
}
