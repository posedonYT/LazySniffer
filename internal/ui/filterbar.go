package ui

import (
	"errors"
	"github.com/poseydon/lazysniffer/internal/deep"
	"sort"
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/dissect"
)

// lineEdit is a single-line text editor.
type lineEdit struct {
	buf []rune
	pos int
}

func (e *lineEdit) text() string { return string(e.buf) }

func (e *lineEdit) set(s string) {
	e.buf = []rune(s)
	e.pos = len(e.buf)
}

func (e *lineEdit) insert(s string) {
	r := []rune(s)
	e.buf = append(e.buf[:e.pos], append(r, e.buf[e.pos:]...)...)
	e.pos += len(r)
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' || r == '-'
}

// edit applies an editing key and reports whether it was consumed.
func (e *lineEdit) edit(k tea.KeyPressMsg) bool {
	switch k.String() {
	case "left", "ctrl+b":
		e.pos = max(e.pos-1, 0)
	case "right", "ctrl+f":
		e.pos = min(e.pos+1, len(e.buf))
	case "home", "ctrl+a":
		e.pos = 0
	case "end", "ctrl+e":
		e.pos = len(e.buf)
	case "backspace", "ctrl+h":
		if e.pos > 0 {
			e.buf = append(e.buf[:e.pos-1], e.buf[e.pos:]...)
			e.pos--
		}
	case "delete", "ctrl+d":
		if e.pos < len(e.buf) {
			e.buf = append(e.buf[:e.pos], e.buf[e.pos+1:]...)
		}
	case "ctrl+u":
		e.buf = e.buf[e.pos:]
		e.pos = 0
	case "ctrl+k":
		e.buf = e.buf[:e.pos]
	case "ctrl+w", "alt+backspace":
		start := e.pos
		for start > 0 && e.buf[start-1] == ' ' {
			start--
		}
		for start > 0 && e.buf[start-1] != ' ' {
			start--
		}
		e.buf = append(e.buf[:start], e.buf[e.pos:]...)
		e.pos = start
	case "alt+left", "alt+b", "ctrl+left":
		for e.pos > 0 && e.buf[e.pos-1] == ' ' {
			e.pos--
		}
		for e.pos > 0 && e.buf[e.pos-1] != ' ' {
			e.pos--
		}
	case "alt+right", "alt+f", "ctrl+right":
		for e.pos < len(e.buf) && e.buf[e.pos] == ' ' {
			e.pos++
		}
		for e.pos < len(e.buf) && e.buf[e.pos] != ' ' {
			e.pos++
		}
	default:
		if k.Text != "" && k.Mod&^tea.ModShift == 0 {
			e.insert(k.Text)
			return true
		}
		return false
	}
	return true
}

// wordAtCursor returns the field-name-like word ending at the cursor.
func (e *lineEdit) wordAtCursor() (string, int) {
	start := e.pos
	for start > 0 && isWordRune(e.buf[start-1]) {
		start--
	}
	return string(e.buf[start:e.pos]), start
}

func (m *App) focusFilter() tea.Cmd {
	m.fbarPrev = m.fbar.text()
	m.setFocus(paneFilter)
	m.histIdx = -1
	m.filterChanged()
	return nil
}

// filterChanged validates the filter text and refreshes suggestions.
func (m *App) filterChanged() {
	text := m.fbar.text()
	m.fbarErr, m.fbarWarn = nil, ""
	if strings.TrimSpace(text) != "" {
		f, err := dfilter.Compile(text)
		var fe *dfilter.Error
		switch {
		case errors.As(err, &fe) && fe.Unknown != "" && deep.Available():
			m.fbarWarn = "field not native: the deep engine (Wireshark) will evaluate this filter"
		case errors.As(err, &fe):
			m.fbarErr = fe
		case err != nil:
			m.fbarErr = &dfilter.Error{Msg: err.Error()}
		case len(f.Warnings) > 0:
			m.fbarWarn = f.Warnings[0]
		}
	}
	m.updateSuggestions()
}

func (m *App) updateSuggestions() {
	m.suggest, m.suggestIdx = nil, 0
	word, _ := m.fbar.wordAtCursor()
	if len(word) < 1 || m.fbar.pos < len(m.fbar.buf) && isWordRune(m.fbar.buf[m.fbar.pos]) {
		return
	}
	// Do not suggest after a comparison operator (we are typing a value).
	before := strings.TrimRight(string(m.fbar.buf[:m.fbar.pos-len([]rune(word))]), " ")
	for _, op := range []string{"==", "!=", ">", "<", "=", "contains", "matches", "~", "in {", "{"} {
		if strings.HasSuffix(before, op) {
			return
		}
	}
	lw := strings.ToLower(word)
	var prefix, contains []*dissect.FieldDef
	for _, f := range dissect.Fields() {
		if strings.HasPrefix(f.Abbrev, "_ws.") && !strings.HasPrefix(lw, "_") {
			continue
		}
		a := strings.ToLower(f.Abbrev)
		switch {
		case a == lw:
			// exact: still useful to show children
			prefix = append(prefix, f)
		case strings.HasPrefix(a, lw):
			prefix = append(prefix, f)
		case len(lw) >= 3 && (strings.Contains(a, lw) || strings.Contains(strings.ToLower(f.Name), lw)):
			contains = append(contains, f)
		}
	}
	// Show direct children before deeper fields: "tcp." → tcp.port before tcp.options.sack_le.
	sort.SliceStable(prefix, func(i, j int) bool {
		return strings.Count(prefix[i].Abbrev, ".") < strings.Count(prefix[j].Abbrev, ".")
	})
	m.suggest = append(prefix, contains...)
	if len(m.suggest) > 200 {
		m.suggest = m.suggest[:200]
	}
	if len(m.suggest) == 1 && strings.EqualFold(m.suggest[0].Abbrev, word) {
		m.suggest = nil
	}
}

func (m *App) acceptSuggestion() {
	if len(m.suggest) == 0 {
		return
	}
	f := m.suggest[m.suggestIdx]
	_, start := m.fbar.wordAtCursor()
	m.fbar.buf = append(m.fbar.buf[:start], append([]rune(f.Abbrev), m.fbar.buf[m.fbar.pos:]...)...)
	m.fbar.pos = start + len([]rune(f.Abbrev))
	m.filterChanged()
	m.suggest = nil
}

func (m *App) filterKey(k tea.KeyPressMsg) tea.Cmd {
	switch k.String() {
	case "enter":
		if len(m.suggest) > 0 && (m.suggestIdx > 0 || m.fbarErr != nil) {
			m.acceptSuggestion()
			return nil
		}
		m.suggest = nil
		text := strings.TrimSpace(m.fbar.text())
		if m.fbarErr != nil && text != "" {
			return m.setFlash(true, "%s", m.fbarErr.Msg)
		}
		m.setFocus(m.single)
		return m.applyFilter(text)
	case "esc":
		if len(m.suggest) > 0 {
			m.suggest = nil
			return nil
		}
		m.fbar.set(m.fbarPrev)
		m.filterChanged()
		m.suggest = nil
		m.setFocus(m.single)
		return nil
	case "tab":
		if len(m.suggest) > 0 {
			m.acceptSuggestion()
		}
		return nil
	case "down", "ctrl+n":
		if len(m.suggest) > 0 {
			m.suggestIdx = (m.suggestIdx + 1) % len(m.suggest)
			return nil
		}
		return m.historyStep(-1)
	case "up", "ctrl+p":
		if len(m.suggest) > 0 {
			m.suggestIdx = (m.suggestIdx - 1 + len(m.suggest)) % len(m.suggest)
			return nil
		}
		return m.historyStep(1)
	}
	if m.fbar.edit(k) {
		m.filterChanged()
	}
	return nil
}

// historyStep walks through previously applied filters (1 = older).
func (m *App) historyStep(d int) tea.Cmd {
	h := m.cfg.FilterHistory
	if len(h) == 0 {
		return nil
	}
	m.histIdx = max(min(m.histIdx+d, len(h)-1), -1)
	if m.histIdx < 0 {
		m.fbar.set(m.fbarPrev)
	} else {
		m.fbar.set(h[m.histIdx])
	}
	m.filterChanged()
	m.suggest = nil
	return nil
}

func (m *App) renderFilterBar() string {
	th := m.theme
	editing := m.focus == paneFilter
	text := m.fbar.text()
	prompt := " Filter "
	ps := lipgloss.NewStyle().Foreground(th.Muted).Bold(true)
	bg := th.BarBG
	status := ""
	stStyle := lipgloss.NewStyle().Foreground(th.Muted).Background(bg)
	switch {
	case strings.TrimSpace(text) == "":
		status = ""
	case m.fbarErr != nil:
		bg = th.ErrBG
		status = "✗ invalid"
		stStyle = stStyle.Foreground(th.Err).Background(bg)
	case m.fbarWarn != "":
		bg = th.WarnBG
		status = "! " + m.fbarWarn
		stStyle = stStyle.Foreground(th.Warn).Background(bg)
	default:
		bg = th.OKBG
		status = "✓ valid"
		if !editing && m.filter != nil && m.filter.Text == text {
			status = "✓ applied"
		} else if !editing {
			status = "✓ not applied — press / then enter"
		}
		stStyle = stStyle.Foreground(th.OK).Background(bg)
	}
	ts := lipgloss.NewStyle().Foreground(th.Text).Background(bg)
	var field string
	if text == "" && !editing {
		field = lipgloss.NewStyle().Foreground(th.Muted).Background(bg).Render("Apply a display filter … press / (e.g. tcp.port == 443 && !dns)")
	} else {
		field = m.renderEditText(ts, bg, editing)
	}
	m.rFilter = rect{0, 1, m.w, 1}
	w := m.w - ansi.StringWidth(prompt) - 1
	st := ""
	if status != "" {
		st = " " + status + " "
	}
	fw := max(w-ansi.StringWidth(st), 10)
	line := ps.Render(prompt) + lipgloss.NewStyle().Background(bg).Render(fit(field, fw)) + stStyle.Render(fit(st, w-fw)) + " "
	return fit(line, m.w)
}

func (m *App) renderEditText(ts lipgloss.Style, bg any, editing bool) string {
	buf := m.fbar.buf
	errStart, errEnd := -1, -1
	if m.fbarErr != nil && m.fbarErr.Len > 0 {
		// Error positions are byte offsets; convert to rune positions.
		s := string(buf)
		if m.fbarErr.Pos <= len(s) {
			errStart = len([]rune(s[:m.fbarErr.Pos]))
			end := min(m.fbarErr.Pos+m.fbarErr.Len, len(s))
			errEnd = len([]rune(s[:end]))
		}
	}
	errSt := ts.Underline(true).Foreground(m.theme.Err)
	cur := ts.Reverse(true)
	var b strings.Builder
	for i, r := range buf {
		st := ts
		if i >= errStart && i < errEnd {
			st = errSt
		}
		if editing && i == m.fbar.pos {
			st = cur
		}
		b.WriteString(st.Render(string(r)))
	}
	if editing && m.fbar.pos >= len(buf) {
		b.WriteString(cur.Render(" "))
	}
	return b.String()
}

// suggestionLayer renders the autocomplete popup under the filter bar.
func (m *App) suggestionLayer() *lipgloss.Layer {
	if m.focus != paneFilter {
		return nil
	}
	th := m.theme
	var lines []string
	maxRows := min(10, m.h-6)
	if len(m.suggest) > 0 && maxRows > 0 {
		start := 0
		if m.suggestIdx >= maxRows {
			start = m.suggestIdx - maxRows + 1
		}
		width := 0
		for i := start; i < len(m.suggest) && i < start+maxRows; i++ {
			width = max(width, len(m.suggest[i].Abbrev)+len(m.suggest[i].Name)+4)
		}
		width = min(width, m.w-12)
		for i := start; i < len(m.suggest) && i < start+maxRows; i++ {
			f := m.suggest[i]
			st := lipgloss.NewStyle().Background(th.MenuBG).Foreground(th.MenuFG)
			ds := st.Foreground(th.Muted)
			if i == m.suggestIdx {
				st = st.Background(th.MenuSelBG).Foreground(th.MenuSelFG)
				ds = ds.Background(th.MenuSelBG).Foreground(th.MenuSelFG)
			}
			line := st.Render(" "+f.Abbrev) + ds.Render("  "+f.Name+" ")
			lines = append(lines, lipgloss.NewStyle().Background(th.MenuBG).Render(fit(line, width)))
		}
		if len(m.suggest) > maxRows {
			lines = append(lines, lipgloss.NewStyle().Background(th.MenuBG).Foreground(th.Muted).Render(fit(" ↑↓ tab to complete · "+commas(len(m.suggest))+" fields", width)))
		}
	}
	if m.fbarErr != nil && strings.TrimSpace(m.fbar.text()) != "" {
		msg := " " + m.fbarErr.Msg + " "
		if m.fbarErr.Unknown != "" {
			msg += "(not dissected natively) "
		}
		lines = append(lines, lipgloss.NewStyle().Background(th.ErrBG).Foreground(th.Err).Render(msg))
	}
	if len(lines) == 0 {
		return nil
	}
	_, start := m.fbar.wordAtCursor()
	x := min(8+start, max(m.w-lipgloss.Width(strings.Join(lines, "\n"))-1, 0))
	return lipgloss.NewLayer(strings.Join(lines, "\n")).X(x).Y(2).Z(5)
}
