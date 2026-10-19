package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/poseydon/lazysniffer/internal/config"
	"github.com/poseydon/lazysniffer/internal/dissect"
)

// ---- Time shift ----

func (m *App) timeShiftDialog() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	cur := float64(m.cap.TimeShift()) / 1e9
	d := newInput("Time Shift", "Seconds to add to every packet's time (negative to subtract):", strconv.FormatFloat(cur, 'f', -1, 64), func(m *App, v string) tea.Cmd {
		sec, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return m.setFlash(true, "not a number: %q", v)
		}
		m.cap.SetTimeShift(int64(sec * 1e9))
		m.rowCache = nil
		m.dissectSelected()
		return m.setFlash(false, "Time shifted by %g s", sec)
	})
	return m.push(d)
}

// ---- Firewall ACL rules ----

func (m *App) firewallDialog() tea.Cmd {
	pi := m.selPI
	if pi == nil || pi.NetSrc.IsZero() {
		return m.setFlash(true, "Select an IP packet first")
	}
	var items []listItem
	for _, prod := range []string{"iptables", "nftables", "pf (BSD/macOS)", "ipfw", "Cisco IOS ACL"} {
		prod := prod
		items = append(items, listItem{label: prod, run: func(m *App) tea.Cmd {
			return m.showText("Firewall rules: "+prod, firewallRules(pi, prod))
		}})
	}
	return m.push(newList("Firewall ACL Rules for the selected packet", items))
}

func firewallRules(pi *dissect.PacketInfo, product string) []string {
	src, dst := pi.NetSrc.String(), pi.NetDst.String()
	proto := ""
	switch pi.PortType {
	case dissect.PortTCP:
		proto = "tcp"
	case dissect.PortUDP:
		proto = "udp"
	case dissect.PortSCTP:
		proto = "sctp"
	}
	v6 := pi.NetSrc.Type == dissect.AddrIPv6
	sp, dp := pi.SrcPort, pi.DstPort
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	switch {
	case strings.HasPrefix(product, "iptables"):
		cmd := "iptables"
		if v6 {
			cmd = "ip6tables"
		}
		add("# deny this flow (inbound to this host)")
		if proto != "" {
			add("%s -A INPUT -s %s -d %s -p %s --sport %d --dport %d -j DROP", cmd, src, dst, proto, sp, dp)
			add("%s -A INPUT -s %s -p %s --dport %d -j DROP   # any source port", cmd, src, proto, dp)
		} else {
			add("%s -A INPUT -s %s -d %s -j DROP", cmd, src, dst)
		}
		add("# allow instead")
		add("%s -A INPUT -s %s -d %s %s -j ACCEPT", cmd, src, dst, portArgs(proto, sp, dp))
	case strings.HasPrefix(product, "nftables"):
		fam := "ip"
		if v6 {
			fam = "ip6"
		}
		add("# deny")
		if proto != "" {
			add("nft add rule inet filter input %s saddr %s %s daddr %s %s sport %d %s dport %d drop", fam, src, fam, dst, proto, sp, proto, dp)
		} else {
			add("nft add rule inet filter input %s saddr %s %s daddr %s drop", fam, src, fam, dst)
		}
	case strings.HasPrefix(product, "pf"):
		if proto != "" {
			add("block in quick proto %s from %s port %d to %s port %d", proto, src, sp, dst, dp)
			add("pass in quick proto %s from %s to %s port %d", proto, src, dst, dp)
		} else {
			add("block in quick from %s to %s", src, dst)
		}
	case product == "ipfw":
		if proto != "" {
			add("ipfw add deny %s from %s %d to %s %d in", proto, src, sp, dst, dp)
		} else {
			add("ipfw add deny ip from %s to %s in", src, dst)
		}
	default: // Cisco
		p := proto
		if p == "" {
			p = "ip"
		}
		if proto != "" {
			add("access-list 101 deny %s host %s eq %d host %s eq %d", p, src, sp, dst, dp)
		} else {
			add("access-list 101 deny ip host %s host %s", src, dst)
		}
		add("access-list 101 permit ip any any")
	}
	return out
}

func portArgs(proto string, sp, dp uint32) string {
	if proto == "" {
		return ""
	}
	return fmt.Sprintf("-p %s --sport %d --dport %d", proto, sp, dp)
}

// ---- Filter buttons ----

func (m *App) filterButtonsDialog() tea.Cmd {
	var items []listItem
	for i, b := range m.cfg.FilterButtons {
		i, b := i, b
		items = append(items, listItem{label: b.Name, detail: b.Filter, run: func(m *App) tea.Cmd { m.pop(); return m.applyFilter(b.Filter) }})
		_ = i
	}
	items = append(items, listItem{label: "+ Add button from the current filter…", run: func(m *App) tea.Cmd {
		f := strings.TrimSpace(m.fbar.text())
		if f == "" {
			return m.setFlash(true, "Type a display filter first")
		}
		return m.push(newInput("New filter button", "Button label:", f, func(m *App, name string) tea.Cmd {
			m.cfg.FilterButtons = append(m.cfg.FilterButtons, config.SavedFilter{Name: strings.TrimSpace(name), Filter: f})
			_ = m.cfg.Save()
			m.pop()
			return m.filterButtonsDialog()
		}))
	}})
	if len(m.cfg.FilterButtons) > 0 {
		items = append(items, listItem{label: "− Remove the last button", run: func(m *App) tea.Cmd {
			m.cfg.FilterButtons = m.cfg.FilterButtons[:len(m.cfg.FilterButtons)-1]
			_ = m.cfg.Save()
			m.pop()
			return m.filterButtonsDialog()
		}})
	}
	return m.push(newList("Display Filter Buttons", items))
}

// ---- Expression builder ----

var exprOps = []string{"==", "!=", ">", "<", ">=", "<=", "contains", "matches", "in"}

func (m *App) expressionDialog() tea.Cmd {
	var items []listItem
	for _, p := range dissect.Protocols() {
		p := p
		if strings.HasPrefix(p.Filter, "_") {
			continue
		}
		items = append(items, listItem{label: p.Filter, detail: p.Name, run: func(m *App) tea.Cmd { return m.expressionFields(p) }})
	}
	return m.push(newList("Filter Expression: protocol", items))
}

func (m *App) expressionFields(p *dissect.Proto) tea.Cmd {
	var items []listItem
	items = append(items, listItem{label: p.Filter, detail: "protocol present", run: func(m *App) tea.Cmd { return m.expressionInsert(p.Filter) }})
	fields := dissect.FieldsWithPrefix(p.Filter + ".")
	sort.Slice(fields, func(i, j int) bool { return fields[i].Abbrev < fields[j].Abbrev })
	for _, f := range fields {
		f := f
		if f.Type == dissect.FtNone || f.Type == dissect.FtProtocol {
			items = append(items, listItem{label: f.Abbrev, detail: f.Name, run: func(m *App) tea.Cmd { return m.expressionInsert(f.Abbrev) }})
			continue
		}
		items = append(items, listItem{label: f.Abbrev, detail: f.Name + " · " + f.Type.String(), run: func(m *App) tea.Cmd { return m.expressionOp(f) }})
	}
	return m.push(newList("Filter Expression: "+p.Name+" field", items))
}

func (m *App) expressionOp(f *dissect.FieldDef) tea.Cmd {
	var items []listItem
	items = append(items, listItem{label: "is present", run: func(m *App) tea.Cmd { return m.expressionInsert(f.Abbrev) }})
	for _, op := range exprOps {
		op := op
		items = append(items, listItem{label: op, run: func(m *App) tea.Cmd {
			return m.push(newInput("Value", f.Abbrev+" "+op+" …", "", func(m *App, v string) tea.Cmd {
				v = strings.TrimSpace(v)
				if f.Type == dissect.FtString && !strings.HasPrefix(v, `"`) {
					v = strconv.Quote(v)
				}
				return m.expressionInsert(fmt.Sprintf("%s %s %s", f.Abbrev, op, v))
			}))
		}})
	}
	return m.push(newList("Filter Expression: "+f.Abbrev, items))
}

// expressionInsert puts the finished expression into the filter bar.
func (m *App) expressionInsert(expr string) tea.Cmd {
	for len(m.overlays()) > 0 {
		m.pop()
	}
	cur := strings.TrimSpace(m.fbar.text())
	if cur != "" {
		expr = cur + " && " + expr
	}
	m.fbar.set(expr)
	return m.focusFilter()
}

// ---- Profiles ----

func (m *App) profilesDialog() tea.Cmd {
	var items []listItem
	for _, p := range config.Profiles() {
		p := p
		name := p
		if p == "Default" {
			name = ""
		}
		mark := ""
		if name == config.Profile {
			mark = "● "
		}
		items = append(items, listItem{label: mark + p, run: func(m *App) tea.Cmd { m.pop(); return m.switchProfile(name) }})
	}
	items = append(items, listItem{label: "+ New profile (copy of the current one)…", run: func(m *App) tea.Cmd {
		return m.push(newInput("New profile", "Profile name:", "", func(m *App, name string) tea.Cmd {
			name = strings.TrimSpace(name)
			if name == "" || strings.ContainsAny(name, `/\.`) {
				return m.setFlash(true, "Use a simple name")
			}
			dir := filepath.Join(config.BaseDir(), "profiles", name)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return m.setFlash(true, "%v", err)
			}
			for _, f := range []string{"config.yml", "colorfilters"} {
				if b, err := os.ReadFile(filepath.Join(config.Dir(), f)); err == nil {
					_ = os.WriteFile(filepath.Join(dir, f), b, 0o644)
				}
			}
			m.pop()
			return m.switchProfile(name)
		}))
	}})
	return m.push(newList("Configuration Profiles", items))
}

func (m *App) switchProfile(name string) tea.Cmd {
	config.Profile = name
	cfg, err := config.Load()
	if err != nil {
		return m.setFlash(true, "%v", err)
	}
	*m.cfg = *cfg
	applyProtocolPrefs(m.cfg)
	m.loadColorRules()
	m.colorize = m.cfg.ColorRows
	m.setupRows()
	if m.cap != nil {
		m.rowCache = nil
		m.dissectSelected()
	}
	label := name
	if label == "" {
		label = "Default"
	}
	return m.setFlash(false, "Profile: %s", label)
}
