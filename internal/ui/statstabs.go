package ui

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/export"
	"github.com/poseydon/lazysniffer/internal/follow"
	"github.com/poseydon/lazysniffer/internal/resolve"
	"github.com/poseydon/lazysniffer/internal/stats"
)

func hb(n uint64) string { return humanBytes(int64(n)) }

// scopeFrames returns the frames a statistic covers: the displayed ones
// when limited, otherwise nil (all).
func (m *App) scopeFrames(limit bool) []uint32 {
	if limit && m.filter != nil && !m.filter.Empty() {
		return append([]uint32{}, m.displayed...)
	}
	return nil
}

func addrLabel(m *App, a fmt.Stringer, port uint32, tcpudp bool) string {
	s := a.String()
	if tcpudp {
		return fmt.Sprintf("%s:%d", s, port)
	}
	return s
}

// openConversations shows Statistics → Conversations.
func (m *App) openConversations() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	t := &tableTab{name: "Conversations", extra: [][2]string{{"a", "apply as filter"}, {"p", "prepare"}, {"f", "follow stream"}, {"d", "limit to display filter"}}}
	limit := false
	build := func(m *App, t *tableTab) error {
		frames := m.scopeFrames(limit)
		t.sets = nil
		for _, k := range stats.Kinds {
			cs, err := stats.Conversations(context.Background(), m.cap, frames, k)
			if err != nil {
				return err
			}
			tcpudp := k == stats.TCP || k == stats.UDP
			cols := []tcol{{"Address A", 0, false}, {"Address B", 0, false}, {"Packets", 9, true}, {"Bytes", 10, true}, {"A→B pkts", 9, true},
				{"A→B bytes", 10, true}, {"B→A pkts", 9, true}, {"B→A bytes", 10, true}, {"Start", 10, true}, {"Duration", 9, true}}
			if tcpudp {
				cols = append([]tcol{{"Stream", 7, true}}, cols...)
			}
			set := &tableSet{name: fmt.Sprintf("%s · %d", k, len(cs)), cols: cols, sortCol: 0}
			var total uint64
			for _, cv := range cs {
				total += cv.Bytes()
				cells := []string{addrLabel(m, cv.A, cv.PortA, tcpudp), addrLabel(m, cv.B, cv.PortB, tcpudp), commas(int(cv.Packets())), hb(cv.Bytes()),
					commas(int(cv.PktsAB)), hb(cv.BytesAB), commas(int(cv.PktsBA)), hb(cv.BytesBA),
					fmt.Sprintf("%.6f", float64(cv.FirstTS)/1e9), fmt.Sprintf("%.4f", cv.Duration())}
				keys := []float64{float64(cv.FirstFrame), 0, float64(cv.Packets()), float64(cv.Bytes()), float64(cv.PktsAB), float64(cv.BytesAB), float64(cv.PktsBA), float64(cv.BytesBA), float64(cv.FirstTS), cv.Duration()}
				if tcpudp {
					cells = append([]string{fmt.Sprint(cv.Stream)}, cells...)
					keys = append([]float64{float64(cv.Stream)}, keys...)
				}
				set.rows = append(set.rows, trow{cells: cells, keys: keys, filter: cv.Filter(), data: cv})
			}
			set.sortRows()
			set.foot = fmt.Sprintf("%s conversations · %s", commas(len(cs)), hb(total))
			t.sets = append(t.sets, set)
		}
		if t.cur >= len(t.sets) {
			t.cur = 0
		}
		scope := "all packets"
		if limit {
			scope = "displayed packets"
		}
		t.subtitle = scope
		return nil
	}
	t.refresh = build
	t.onKey = func(m *App, t *tableTab, row *trow, key string) (tea.Cmd, bool) {
		switch key {
		case "d":
			limit = !limit
			if err := build(m, t); err != nil {
				return m.setFlash(true, "%v", err), true
			}
			return nil, true
		case "f":
			if row != nil {
				if cv, ok := row.data.(*stats.Conv); ok && cv.Stream >= 0 {
					m.tab = -1
					return m.followByFilter(cv.Filter()), true
				}
			}
		}
		return nil, false
	}
	if err := build(m, t); err != nil {
		return m.setFlash(true, "Conversations: %v", err)
	}
	// Start on the most useful table: the first non-empty one of TCP, UDP, IPv4, Ethernet.
	t.cur = firstNonEmpty(t, "TCP", "UDP", "IPv4", "Ethernet")
	m.openUniqueTab(t)
	return nil
}

func firstNonEmpty(t *tableTab, prefs ...string) int {
	for _, p := range prefs {
		for i, s := range t.sets {
			if strings.HasPrefix(s.name, p) && len(s.rows) > 0 {
				return i
			}
		}
	}
	return 0
}

// followByFilter opens Follow Stream for the stream selected by a
// "tcp.stream eq N" / "udp.stream eq N" filter.
func (m *App) followByFilter(f string) tea.Cmd {
	var idx uint32
	var kind string
	if _, err := fmt.Sscanf(f, "tcp.stream eq %d", &idx); err == nil {
		kind = "tcp"
	} else if _, err := fmt.Sscanf(f, "udp.stream eq %d", &idx); err == nil {
		kind = "udp"
	} else {
		return nil
	}
	if kind == "tcp" {
		return m.openFollow(follow.TCP, idx, m.fbar.text())
	}
	return m.openFollow(follow.UDP, idx, m.fbar.text())
}

// openEndpoints shows Statistics → Endpoints.
func (m *App) openEndpoints() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	t := &tableTab{name: "Endpoints", extra: [][2]string{{"a", "apply as filter"}, {"p", "prepare"}, {"d", "limit to display filter"}}}
	limit := false
	build := func(m *App, t *tableTab) error {
		frames := m.scopeFrames(limit)
		t.sets = nil
		for _, k := range stats.Kinds {
			es, err := stats.Endpoints(context.Background(), m.cap, frames, k)
			if err != nil {
				return err
			}
			tcpudp := k == stats.TCP || k == stats.UDP
			cols := []tcol{{"Address", 0, false}, {"Packets", 9, true}, {"Bytes", 10, true}, {"Tx pkts", 9, true}, {"Tx bytes", 10, true}, {"Rx pkts", 9, true}, {"Rx bytes", 10, true}}
			if tcpudp {
				cols = []tcol{{"Address", 0, false}, {"Port", 7, true}, {"Packets", 9, true}, {"Bytes", 10, true}, {"Tx pkts", 9, true}, {"Tx bytes", 10, true}, {"Rx pkts", 9, true}, {"Rx bytes", 10, true}}
			}
			geo := resolve.GeoAvailable() && k != stats.Ethernet
			if geo {
				cols = append(cols, tcol{"Country", 8, false}, tcol{"City", 16, false}, tcol{"AS", 0, false})
			}
			set := &tableSet{name: fmt.Sprintf("%s · %d", k, len(es)), cols: cols}
			for _, e := range es {
				cells := []string{m.resolveAddr(e.Addr), commas(int(e.Packets())), hb(e.Bytes()), commas(int(e.TxP)), hb(e.TxB), commas(int(e.RxP)), hb(e.RxB)}
				keys := []float64{float64(e.First), float64(e.Packets()), float64(e.Bytes()), float64(e.TxP), float64(e.TxB), float64(e.RxP), float64(e.RxB)}
				if tcpudp {
					cells = append(cells[:1], append([]string{fmt.Sprint(e.Port)}, cells[1:]...)...)
					keys = append(keys[:1], append([]float64{float64(e.Port)}, keys[1:]...)...)
				}
				if geo {
					gi, _ := resolve.GeoLookup(addrOf(e.Addr))
					as := ""
					if gi.ASN != 0 {
						as = fmt.Sprintf("AS%d %s", gi.ASN, gi.Org)
					}
					cells = append(cells, gi.Country, gi.City, as)
					keys = append(keys, 0, 0, float64(gi.ASN))
				}
				set.rows = append(set.rows, trow{cells: cells, keys: keys, filter: e.Filter(), frame: 0})
			}
			set.sortRows()
			t.sets = append(t.sets, set)
		}
		if t.cur >= len(t.sets) {
			t.cur = 0
		}
		t.subtitle = map[bool]string{false: "all packets", true: "displayed packets"}[limit]
		return nil
	}
	t.refresh = build
	t.onKey = func(m *App, t *tableTab, row *trow, key string) (tea.Cmd, bool) {
		if key == "d" {
			limit = !limit
			if err := build(m, t); err != nil {
				return m.setFlash(true, "%v", err), true
			}
			return nil, true
		}
		return nil, false
	}
	if err := build(m, t); err != nil {
		return m.setFlash(true, "Endpoints: %v", err)
	}
	t.cur = firstNonEmpty(t, "IPv4", "IPv6", "Ethernet", "TCP", "UDP")
	m.openUniqueTab(t)
	return nil
}

// openHierarchy shows Statistics → Protocol Hierarchy.
func (m *App) openHierarchy() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	t := &tableTab{name: "Protocol Hierarchy", noSort: true, extra: [][2]string{{"a", "apply as filter"}, {"p", "prepare"}, {"d", "limit to display filter"}}}
	limit := false
	build := func(m *App, t *tableTab) error {
		root, err := stats.Hierarchy(context.Background(), m.cap, m.scopeFrames(limit))
		if err != nil {
			return err
		}
		set := &tableSet{name: "Protocols", cols: []tcol{{"Protocol", 0, false}, {"% Packets", 10, true}, {"Packets", 10, true}, {"% Bytes", 9, true}, {"Bytes", 11, true}, {"End Packets", 12, true}, {"End Bytes", 11, true}}}
		var walk func(n *stats.PHS, depth int)
		walk = func(n *stats.PHS, depth int) {
			name := n.Name
			filter := n.Name
			if p := protoNames()[n.Name]; p != "" {
				name = p + " (" + n.Name + ")"
			}
			if n.Name == "frame" {
				name, filter = "Frame", ""
			}
			set.rows = append(set.rows, trow{indent: depth, filter: filter, cells: []string{name,
				fmt.Sprintf("%.1f", 100*float64(n.Packets)/float64(max(root.Packets, 1))), commas(int(n.Packets)),
				fmt.Sprintf("%.1f", 100*float64(n.Bytes)/float64(max(root.Bytes, 1))), hb(n.Bytes), commas(int(n.EndP)), hb(n.EndB)}})
			for _, ch := range n.Children {
				walk(ch, depth+1)
			}
		}
		walk(root, 0)
		t.sets = []*tableSet{set}
		t.subtitle = map[bool]string{false: "all packets", true: "displayed packets"}[limit]
		return nil
	}
	t.refresh = build
	t.onKey = func(m *App, t *tableTab, row *trow, key string) (tea.Cmd, bool) {
		if key == "d" {
			limit = !limit
			if err := build(m, t); err != nil {
				return m.setFlash(true, "%v", err), true
			}
			return nil, true
		}
		return nil, false
	}
	if err := build(m, t); err != nil {
		return m.setFlash(true, "Protocol Hierarchy: %v", err)
	}
	m.openUniqueTab(t)
	return nil
}

// openPacketLengths shows Statistics → Packet Lengths.
func (m *App) openPacketLengths() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	t := &tableTab{name: "Packet Lengths", noSort: true}
	build := func(m *App, t *tableTab) error {
		bins, err := stats.Lengths(context.Background(), m.cap, m.scopeFrames(true))
		if err != nil {
			return err
		}
		var total, peak uint64
		for _, b := range bins {
			total += b.Count
			peak = max(peak, b.Count)
		}
		set := &tableSet{name: "Lengths", cols: []tcol{{"Packet length", 20, false}, {"Count", 10, true}, {"Percent", 9, true}, {"Distribution", 0, false}}}
		for _, b := range bins {
			bar := ""
			if peak > 0 {
				bar = strings.Repeat("█", int(40*b.Count/peak))
			}
			set.rows = append(set.rows, trow{cells: []string{b.Label, commas(int(b.Count)), fmt.Sprintf("%.2f%%", 100*float64(b.Count)/float64(max(total, 1))), bar}})
		}
		t.sets = []*tableSet{set}
		return nil
	}
	t.refresh = build
	if err := build(m, t); err != nil {
		return m.setFlash(true, "Packet Lengths: %v", err)
	}
	m.openUniqueTab(t)
	return nil
}

// openObjects shows File → Export Objects.
func (m *App) openObjects() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	t := &tableTab{name: "Export Objects", extra: [][2]string{{"enter", "go to packet"}, {"e", "save selected"}, {"E", "save all"}, {"a", "filter by URL"}}}
	var objs []export.Object
	build := func(m *App, t *tableTab) error {
		var err error
		objs, err = export.Objects(context.Background(), m.cap)
		if err != nil {
			return err
		}
		set := &tableSet{name: "Objects", cols: []tcol{{"Packet", 8, true}, {"Proto", 9, false}, {"Hostname", 0, false}, {"Content Type", 0, false}, {"Size", 11, true}, {"Filename", 0, false}}}
		var total uint64
		for i, o := range objs {
			total += uint64(o.Size)
			set.rows = append(set.rows, trow{frame: o.Frame, data: i, keys: []float64{float64(o.Frame), 0, 0, 0, float64(o.Size)},
				cells: []string{fmt.Sprint(o.Frame), o.Proto, o.Host, o.Type, hb(uint64(o.Size)), o.Filename}})
		}
		set.foot = fmt.Sprintf("%s objects · %s", commas(len(objs)), hb(total))
		t.sets = []*tableSet{set}
		return nil
	}
	t.refresh = build
	t.onKey = func(m *App, t *tableTab, row *trow, key string) (tea.Cmd, bool) {
		switch key {
		case "e":
			if row == nil {
				return nil, true
			}
			o := objs[row.data.(int)]
			def := filepath.Join(downloadDir(), export.SafeName(o.Filename))
			return m.push(newInput("Save Object", fmt.Sprintf("%s (%s) → file:", o.Filename, hb(uint64(o.Size))), def, func(m *App, v string) tea.Cmd {
				path := expandHome(strings.TrimSpace(v))
				data, err := export.ObjectBytes(m.cap, o)
				if err != nil {
					return m.setFlash(true, "%v", err)
				}
				if err := os.WriteFile(path, data, 0o644); err != nil {
					return m.setFlash(true, "%v", err)
				}
				return m.setFlash(false, "Saved %s", path)
			})), true
		case "E":
			def := filepath.Join(downloadDir(), "lazysniffer-objects")
			return m.push(newInput("Save All Objects", fmt.Sprintf("%d objects → directory:", len(objs)), def, func(m *App, v string) tea.Cmd {
				n, err := export.SaveObjects(m.cap, objs, expandHome(strings.TrimSpace(v)))
				if err != nil {
					return m.setFlash(true, "%v (saved %d)", err, n)
				}
				return m.setFlash(false, "Saved %d objects to %s", n, v)
			})), true
		case "a":
			if row != nil {
				o := objs[row.data.(int)]
				m.tab = -1
				if o.URI != "" {
					return m.applyFilter(fmt.Sprintf(`http.request.full_uri == %q || http2.request.full_uri == %q || http2.body.uri == %q`, o.URI, o.URI, o.URI)), true
				}
				return m.gotoFrame(o.Frame), true
			}
		}
		return nil, false
	}
	if err := build(m, t); err != nil {
		return m.setFlash(true, "Export Objects: %v", err)
	}
	m.openUniqueTab(t)
	if len(objs) == 0 {
		return m.setFlash(false, "No objects found (encrypted traffic needs TLS keys: Edit → TLS Key Log File)")
	}
	return nil
}

func downloadDir() string {
	home, _ := os.UserHomeDir()
	if d := filepath.Join(home, "Downloads"); dirExists(d) {
		return d
	}
	return home
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// openCredentials shows Tools → Credentials.
func (m *App) openCredentials() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	t := &tableTab{name: "Credentials", extra: [][2]string{{"enter", "go to packet"}}}
	build := func(m *App, t *tableTab) error {
		cs, err := export.Credentials(context.Background(), m.cap)
		if err != nil {
			return err
		}
		set := &tableSet{name: "Credentials", cols: []tcol{{"Packet", 8, true}, {"Protocol", 12, false}, {"Username", 0, false}, {"Password", 0, false}, {"Note", 0, false}}}
		for _, c := range cs {
			set.rows = append(set.rows, trow{frame: c.Frame, keys: []float64{float64(c.Frame)}, cells: []string{fmt.Sprint(c.Frame), c.Proto, c.Username, c.Password, c.Note}})
		}
		set.foot = fmt.Sprintf("%d credential(s) sent in clear text", len(cs))
		t.sets = []*tableSet{set}
		return nil
	}
	t.refresh = build
	if err := build(m, t); err != nil {
		return m.setFlash(true, "Credentials: %v", err)
	}
	m.openUniqueTab(t)
	return nil
}

var protoNameMap map[string]string

// protoNames maps filter abbreviations to protocol names.
func protoNames() map[string]string {
	if protoNameMap == nil {
		protoNameMap = map[string]string{}
		for _, p := range dissect.Protocols() {
			protoNameMap[p.Filter] = p.Name
		}
	}
	return protoNameMap
}

func countsSet(name, col string, counts map[string]uint64) *tableSet {
	set := &tableSet{name: name, cols: []tcol{{col, 0, false}, {"Count", 10, true}, {"Percent", 9, true}}}
	var total uint64
	for _, n := range counts {
		total += n
	}
	for k, n := range counts {
		set.rows = append(set.rows, trow{cells: []string{k, commas(int(n)), fmt.Sprintf("%.2f%%", 100*float64(n)/float64(max(total, 1)))}, keys: []float64{0, float64(n), float64(n)}})
	}
	set.sortCol, set.desc = 1, true
	set.sortRows()
	set.foot = fmt.Sprintf("%s total", commas(int(total)))
	return set
}

func numStatLine(label string, n stats.NumStat) string {
	if n.Count == 0 {
		return label + ": no data"
	}
	return fmt.Sprintf("%s: %s samples, min %.3f ms, avg %.3f ms, max %.3f ms", label, commas(int(n.Count)), n.Min*1e3, n.Avg()*1e3, n.Max*1e3)
}

// openHTTPStats shows Statistics → HTTP.
func (m *App) openHTTPStats() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	build := func(m *App, t *tableTab) error {
		tl, err := stats.Tally(context.Background(), m.cap, m.scopeFrames(true), "http.request.method", "http.response.code", "http.request.full_uri", "http.content_type", "http.host")
		if err != nil {
			return err
		}
		times, _ := stats.Numeric(context.Background(), m.cap, m.scopeFrames(true), "http.time")
		t.sets = []*tableSet{
			countsSet("Requests", "Method", tl["http.request.method"]),
			countsSet("Responses", "Status code", tl["http.response.code"]),
			countsSet("Hosts", "Host", tl["http.host"]),
			countsSet("URLs", "Request URI", tl["http.request.full_uri"]),
			countsSet("Content types", "Content-Type", tl["http.content_type"]),
		}
		t.sets[0].foot = numStatLine("Server response time", times)
		t.cur = min(t.cur, len(t.sets)-1)
		return nil
	}
	t := &tableTab{name: "HTTP Statistics", subtitle: "displayed packets", refresh: build, extra: [][2]string{{"a", "apply as filter"}}}
	if err := build(m, t); err != nil {
		return m.setFlash(true, "HTTP: %v", err)
	}
	t.onKey = func(m *App, t *tableTab, row *trow, key string) (tea.Cmd, bool) {
		if key == "a" && row != nil {
			field := map[string]string{"Requests": "http.request.method", "Responses": "http.response.code", "Hosts": "http.host", "URLs": "http.request.full_uri", "Content types": "http.content_type"}[t.set().name]
			val := row.cells[0]
			m.tab = -1
			if field == "http.response.code" {
				return m.applyFilter(fmt.Sprintf("%s == %s", field, val)), true
			}
			return m.applyFilter(fmt.Sprintf("%s == %q", field, val)), true
		}
		return nil, false
	}
	m.openUniqueTab(t)
	return nil
}

// openDNSStats shows Statistics → DNS.
func (m *App) openDNSStats() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	build := func(m *App, t *tableTab) error {
		tl, err := stats.Tally(context.Background(), m.cap, m.scopeFrames(true), "dns.qry.type", "dns.flags.rcode", "dns.qry.name", "dns.resp.type")
		if err != nil {
			return err
		}
		times, _ := stats.Numeric(context.Background(), m.cap, m.scopeFrames(true), "dns.time")
		t.sets = []*tableSet{
			countsSet("Query types", "Type", tl["dns.qry.type"]),
			countsSet("Response codes", "Rcode", tl["dns.flags.rcode"]),
			countsSet("Queried names", "Name", tl["dns.qry.name"]),
			countsSet("Answer types", "Type", tl["dns.resp.type"]),
		}
		t.sets[0].foot = numStatLine("Response time", times)
		t.cur = min(t.cur, len(t.sets)-1)
		return nil
	}
	t := &tableTab{name: "DNS Statistics", subtitle: "displayed packets", refresh: build, extra: [][2]string{{"a", "apply as filter"}}}
	if err := build(m, t); err != nil {
		return m.setFlash(true, "DNS: %v", err)
	}
	t.onKey = func(m *App, t *tableTab, row *trow, key string) (tea.Cmd, bool) {
		if key == "a" && row != nil {
			field := map[string]string{"Query types": "dns.qry.type", "Response codes": "dns.flags.rcode", "Queried names": "dns.qry.name", "Answer types": "dns.resp.type"}[t.set().name]
			m.tab = -1
			if field == "dns.qry.name" {
				return m.applyFilter(fmt.Sprintf("%s == %q", field, row.cells[0])), true
			}
			return m.applyFilter(fmt.Sprintf("%s == %q", field, row.cells[0])), true
		}
		return nil, false
	}
	m.openUniqueTab(t)
	return nil
}

func addrOf(a dissect.Address) netip.Addr {
	ip, _ := netip.ParseAddr(a.String())
	return ip
}
