package ui

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/poseydon/lazysniffer/internal/config"
	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/dissect/proto"
	"github.com/poseydon/lazysniffer/internal/lua"
)

// applyProtocolPrefs installs Decode As entries and disabled protocols
// from the configuration.
func applyProtocolPrefs(cfg *config.Config) {
	for _, t := range dissect.Tables() {
		for k := range t.UserEntries() {
			t.SetUser(k, nil)
		}
	}
	for _, e := range cfg.DecodeAs {
		if h := dissect.FindHandle(e.Handle); h != nil {
			dissect.Table(e.Table).SetUser(e.Value, h)
		}
	}
	off := map[string]bool{}
	for _, n := range cfg.DisabledProtocols {
		off[n] = true
	}
	for _, p := range dissect.Protocols() {
		p.Enabled = !off[p.Filter]
	}
}

func (m *App) decodeAsDialog() tea.Cmd {
	var items []listItem
	add := func(table string, port uint32, label string) {
		items = append(items, listItem{label: label, detail: tableLabel(table), run: func(m *App) tea.Cmd { return m.decodeAsPick(table, uint64(port)) }})
	}
	if pi := m.selPI; pi != nil && pi.PortType != dissect.PortNone {
		table := map[dissect.PortType]string{dissect.PortTCP: "tcp.port", dissect.PortUDP: "udp.port", dissect.PortSCTP: "sctp.port"}[pi.PortType]
		add(table, pi.SrcPort, fmt.Sprintf("Decode source port %d as…", pi.SrcPort))
		if pi.DstPort != pi.SrcPort {
			add(table, pi.DstPort, fmt.Sprintf("Decode destination port %d as…", pi.DstPort))
		}
	}
	for i, e := range m.cfg.DecodeAs {
		i, e := i, e
		items = append(items, listItem{label: fmt.Sprintf("Remove: %s %d → %s", e.Table, e.Value, e.Handle), run: func(m *App) tea.Cmd {
			m.cfg.DecodeAs = append(m.cfg.DecodeAs[:i], m.cfg.DecodeAs[i+1:]...)
			_ = m.cfg.Save()
			applyProtocolPrefs(m.cfg)
			return m.reloadAfterPrefs("Decode As entry removed")
		}})
	}
	if len(items) == 0 {
		return m.setFlash(true, "Select a TCP or UDP packet to decode its port as another protocol")
	}
	return m.push(newList("Decode As", items))
}

func tableLabel(t string) string {
	return map[string]string{"tcp.port": "TCP port", "udp.port": "UDP port", "sctp.port": "SCTP port"}[t]
}

func (m *App) decodeAsPick(table string, port uint64) tea.Cmd {
	var items []listItem
	for _, name := range dissect.HandleNames() {
		name := name
		if h := dissect.FindHandle(name); h == nil || h.Proto == nil {
			continue
		}
		items = append(items, listItem{label: name, detail: dissect.FindHandle(name).Proto.Name, run: func(m *App) tea.Cmd {
			m.pop()
			var kept []config.DecodeAsEntry
			for _, e := range m.cfg.DecodeAs {
				if !(e.Table == table && e.Value == port) {
					kept = append(kept, e)
				}
			}
			m.cfg.DecodeAs = append(kept, config.DecodeAsEntry{Table: table, Value: port, Handle: name})
			_ = m.cfg.Save()
			applyProtocolPrefs(m.cfg)
			return m.reloadAfterPrefs(fmt.Sprintf("%s %d decoded as %s", tableLabel(table), port, name))
		}})
	}
	return m.push(newList(fmt.Sprintf("Decode %s %d as", tableLabel(table), port), items))
}

func (m *App) reloadAfterPrefs(msg string) tea.Cmd {
	if m.cap == nil {
		return m.setFlash(false, "%s", msg)
	}
	return tea.Batch(m.reload(), m.setFlash(false, "%s", msg))
}

// enabledProtocolsDialog toggles protocols on and off.
func (m *App) enabledProtocolsDialog() tea.Cmd {
	protos := dissect.Protocols()
	sort.Slice(protos, func(i, j int) bool { return strings.ToLower(protos[i].Name) < strings.ToLower(protos[j].Name) })
	var items []listItem
	for _, p := range protos {
		p := p
		if p.Filter == "frame" || p.Filter == "eth" || p.Filter == "ip" || p.Filter == "tcp" || p.Filter == "udp" || strings.HasPrefix(p.Filter, "_") {
			continue
		}
		items = append(items, listItem{label: fmt.Sprintf("%s (%s)", p.Name, p.Filter), checked: &p.Enabled, keep: true, run: func(m *App) tea.Cmd {
			p.Enabled = !p.Enabled
			var off []string
			for _, q := range dissect.Protocols() {
				if !q.Enabled {
					off = append(off, q.Filter)
				}
			}
			m.cfg.DisabledProtocols = off
			_ = m.cfg.Save()
			return m.reloadAfterPrefs(fmt.Sprintf("%s %s", p.Name, map[bool]string{true: "enabled", false: "disabled"}[p.Enabled]))
		}})
	}
	return m.push(newList("Enabled Protocols (space toggles)", items))
}

var _ = proto.TCPPortTable

// luaPluginsDialog lists the loaded Lua plugins and load errors.
func (m *App) luaPluginsDialog() tea.Cmd {
	var lines []string
	for _, p := range lua.Loaded() {
		lines = append(lines, fmt.Sprintf("✓ %s — %s", p.Path, strings.Join(p.Protos, ", ")))
	}
	for _, e := range m.opts.LuaErrors {
		lines = append(lines, "✗ "+e.Error())
	}
	if len(lines) == 0 {
		lines = []string{"No Lua plugins loaded.", "", "Put .lua dissectors into " + filepath.Join(config.Dir(), "plugins") + " or pass --lua file.lua."}
	}
	return m.showText("Lua plugins", lines)
}
