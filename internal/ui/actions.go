package ui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
)

// ctx is where a key binding is active.
type ctx uint8

const (
	ctxGlobal ctx = 1 << iota
	ctxList
	ctxDetails
	ctxBytes
	ctxStart
	ctxCapture = ctxList | ctxDetails | ctxBytes // anywhere a capture is open
)

// Action is a user command. Menus, the command palette, key bindings and
// the help screen are all generated from the action registry.
type Action struct {
	ID      string
	Title   string
	Menu    string // top-level menu, "" = palette only
	Group   int    // separator groups inside a menu
	Keys    []string
	Hint    string // short label for the hints bar
	Ctx     ctx
	Run     func(m *App) tea.Cmd
	Enabled func(m *App) bool
}

// Menus in display order (Wireshark's menu bar).
var menuOrder = []string{"File", "Edit", "View", "Go", "Capture", "Analyze", "Statistics", "Telephony", "Wireless", "Tools", "Help"}

func hasCapture(m *App) bool { return m.cap != nil }

func (m *App) buildActions() {
	A := func(a Action) { m.actions = append(m.actions, &a) }
	cap := hasCapture

	// ---- File ----
	A(Action{ID: "file.open", Title: "Open…", Menu: "File", Keys: []string{"o", "ctrl+o"}, Hint: "open", Ctx: ctxGlobal | ctxStart, Run: (*App).openFileDialog})
	A(Action{ID: "file.recent", Title: "Open Recent…", Menu: "File", Keys: []string{"O"}, Ctx: ctxGlobal | ctxStart, Run: (*App).recentDialog})
	A(Action{ID: "file.close", Title: "Close", Menu: "File", Keys: []string{"ctrl+w"}, Ctx: ctxCapture, Run: (*App).closeCapture, Enabled: cap})
	A(Action{ID: "file.reload", Title: "Reload", Menu: "File", Keys: []string{"ctrl+r"}, Ctx: ctxCapture, Run: (*App).reload, Enabled: cap})
	A(Action{ID: "file.saveas", Title: "Save As…", Menu: "File", Group: 1, Keys: []string{"ctrl+s"}, Ctx: ctxCapture, Run: (*App).saveAsDialog, Enabled: cap})
	A(Action{ID: "file.savekeys", Title: "Save With TLS Keys…", Menu: "File", Group: 1, Ctx: ctxCapture, Run: (*App).saveWithKeys, Enabled: cap})
	A(Action{ID: "file.exportkeys", Title: "Export TLS Session Keys…", Menu: "File", Group: 1, Ctx: ctxCapture, Run: (*App).exportKeysDialog, Enabled: cap})
	A(Action{ID: "pref.geoip", Title: "GeoIP Database Folder…", Menu: "Edit", Group: 9, Ctx: ctxGlobal | ctxStart | ctxCapture, Run: (*App).geoipDialog})
	A(Action{ID: "file.merge", Title: "Merge With File…", Menu: "File", Group: 1, Ctx: ctxCapture, Run: (*App).mergeDialog, Enabled: cap})
	A(Action{ID: "pref.keylog", Title: "TLS Key Log File…", Menu: "Edit", Group: 9, Ctx: ctxGlobal | ctxStart | ctxCapture, Run: (*App).keylogDialog})
	A(Action{ID: "file.objects", Title: "Export Objects…", Menu: "File", Group: 1, Keys: []string{"ctrl+e"}, Ctx: ctxCapture, Run: (*App).openObjects, Enabled: cap})
	A(Action{ID: "file.dissections", Title: "Export Packet Dissections…", Menu: "File", Group: 1, Ctx: ctxCapture, Run: (*App).exportDissectionsDialog, Enabled: cap})
	A(Action{ID: "file.export", Title: "Export Specified Packets…", Menu: "File", Group: 1, Ctx: ctxCapture, Run: (*App).exportDialog, Enabled: cap})
	A(Action{ID: "file.props", Title: "Capture File Properties", Menu: "Statistics", Keys: []string{"ctrl+alt+shift+c"}, Ctx: ctxCapture, Run: (*App).propertiesDialog, Enabled: cap})
	A(Action{ID: "file.quit", Title: "Quit", Menu: "File", Group: 9, Keys: []string{"q", "ctrl+c"}, Hint: "quit", Ctx: ctxGlobal | ctxStart, Run: (*App).quit})

	// ---- Edit ----
	A(Action{ID: "edit.copy", Title: "Copy…", Menu: "Edit", Keys: []string{"y"}, Hint: "copy", Ctx: ctxCapture, Run: (*App).copyMenu, Enabled: cap})
	A(Action{ID: "edit.find", Title: "Find Packet…", Menu: "Edit", Keys: []string{"ctrl+f"}, Ctx: ctxCapture, Run: (*App).findDialog, Enabled: cap})
	A(Action{ID: "edit.findnext", Title: "Find Next", Menu: "Edit", Keys: []string{"n"}, Ctx: ctxCapture, Run: func(m *App) tea.Cmd { return m.findNext(1) }, Enabled: cap})
	A(Action{ID: "edit.findprev", Title: "Find Previous", Menu: "Edit", Keys: []string{"N"}, Ctx: ctxCapture, Run: func(m *App) tea.Cmd { return m.findNext(-1) }, Enabled: cap})
	A(Action{ID: "edit.mark", Title: "Mark/Unmark Packet", Menu: "Edit", Group: 1, Keys: []string{"m"}, Hint: "mark", Ctx: ctxCapture, Run: (*App).toggleMark, Enabled: cap})
	A(Action{ID: "edit.markall", Title: "Mark All Displayed", Menu: "Edit", Group: 1, Keys: []string{"ctrl+alt+m"}, Ctx: ctxCapture, Run: (*App).markAllDisplayed, Enabled: cap})
	A(Action{ID: "edit.unmarkall", Title: "Unmark All Displayed", Menu: "Edit", Group: 1, Keys: []string{"M"}, Ctx: ctxCapture, Run: (*App).unmarkAll, Enabled: cap})
	A(Action{ID: "edit.nextmark", Title: "Next Mark", Menu: "Edit", Group: 1, Keys: []string{"alt+n"}, Ctx: ctxCapture, Run: func(m *App) tea.Cmd { return m.gotoFlagged(1) }, Enabled: cap})
	A(Action{ID: "edit.prevmark", Title: "Previous Mark", Menu: "Edit", Group: 1, Keys: []string{"alt+b"}, Ctx: ctxCapture, Run: func(m *App) tea.Cmd { return m.gotoFlagged(-1) }, Enabled: cap})
	A(Action{ID: "edit.ignore", Title: "Ignore/Unignore Packet", Menu: "Edit", Group: 2, Keys: []string{"i"}, Ctx: ctxCapture, Run: (*App).toggleIgnore, Enabled: cap})
	A(Action{ID: "edit.unignoreall", Title: "Unignore All", Menu: "Edit", Group: 2, Ctx: ctxCapture, Run: (*App).unignoreAll, Enabled: cap})
	A(Action{ID: "edit.timeref", Title: "Set/Unset Time Reference", Menu: "Edit", Group: 3, Keys: []string{"t"}, Ctx: ctxCapture, Run: (*App).toggleTimeRef, Enabled: cap})
	A(Action{ID: "edit.untimeref", Title: "Unset All Time References", Menu: "Edit", Group: 3, Ctx: ctxCapture, Run: (*App).clearTimeRefs, Enabled: cap})
	A(Action{ID: "edit.comment", Title: "Packet Comment…", Menu: "Edit", Group: 4, Keys: []string{"C"}, Ctx: ctxCapture, Run: (*App).commentDialog, Enabled: cap})
	A(Action{ID: "edit.prefs", Title: "Preferences…", Menu: "Edit", Group: 9, Ctx: ctxGlobal | ctxStart, Run: (*App).prefsDialog})

	// ---- View ----
	A(Action{ID: "view.timefmt", Title: "Time Display Format…", Menu: "View", Keys: []string{"T"}, Ctx: ctxCapture, Run: (*App).timeFormatMenu, Enabled: cap})
	A(Action{ID: "view.resolve", Title: "Name Resolution…", Menu: "View", Ctx: ctxCapture, Run: (*App).resolutionMenu, Enabled: cap})
	A(Action{ID: "view.colorize", Title: "Colorize Packet List", Menu: "View", Group: 1, Keys: []string{"ctrl+k"}, Ctx: ctxCapture, Run: (*App).toggleColorize, Enabled: cap})
	A(Action{ID: "view.colorstyle", Title: "Coloring Style (Background/Text)", Menu: "View", Group: 1, Ctx: ctxCapture, Run: (*App).toggleColorStyle, Enabled: cap})
	A(Action{ID: "view.process", Title: "Show Process Column", Menu: "View", Group: 1, Ctx: ctxCapture, Run: (*App).toggleProcessColumn, Enabled: cap})
	A(Action{ID: "view.zoom", Title: "Maximize/Restore Pane", Menu: "View", Group: 2, Keys: []string{"+", "="}, Hint: "zoom", Ctx: ctxCapture, Run: (*App).toggleZoom, Enabled: cap})
	A(Action{ID: "view.expandsub", Title: "Expand Subtrees", Menu: "View", Group: 3, Keys: []string{"e"}, Ctx: ctxDetails, Run: (*App).expandSubtree, Enabled: cap})
	A(Action{ID: "view.collapsesub", Title: "Collapse Subtrees", Menu: "View", Group: 3, Keys: []string{"w"}, Ctx: ctxDetails, Run: (*App).collapseSubtree, Enabled: cap})
	A(Action{ID: "view.expandall", Title: "Expand All", Menu: "View", Group: 3, Keys: []string{"E"}, Ctx: ctxDetails, Run: (*App).expandAll, Enabled: cap})
	A(Action{ID: "view.collapseall", Title: "Collapse All", Menu: "View", Group: 3, Keys: []string{"W"}, Ctx: ctxDetails, Run: (*App).collapseAll, Enabled: cap})
	A(Action{ID: "view.bits", Title: "Show Bytes as Bits/Hex", Menu: "View", Group: 4, Keys: []string{"b"}, Ctx: ctxBytes, Run: (*App).toggleBits, Enabled: cap})
	A(Action{ID: "view.datasource", Title: "Next Bytes Data Source", Menu: "View", Group: 4, Keys: []string{"d"}, Ctx: ctxBytes, Run: (*App).nextDataSource, Enabled: cap})
	A(Action{ID: "view.packettab", Title: "Show Packet in New Tab", Menu: "View", Group: 5, Ctx: ctxCapture, Run: (*App).packetTab, Enabled: cap})
	A(Action{ID: "view.theme", Title: "Toggle Dark/Light Theme", Menu: "View", Group: 6, Ctx: ctxGlobal | ctxStart, Run: (*App).toggleTheme})

	// ---- Go ----
	A(Action{ID: "go.goto", Title: "Go to Packet…", Menu: "Go", Keys: []string{"ctrl+g", ":"}, Ctx: ctxCapture, Run: (*App).gotoDialog, Enabled: cap})
	A(Action{ID: "go.back", Title: "Back", Menu: "Go", Keys: []string{"alt+left", "backspace"}, Ctx: ctxCapture, Run: func(m *App) tea.Cmd { return m.historyMove(-1) }, Enabled: cap})
	A(Action{ID: "go.forward", Title: "Forward", Menu: "Go", Keys: []string{"alt+right"}, Ctx: ctxCapture, Run: func(m *App) tea.Cmd { return m.historyMove(1) }, Enabled: cap})
	A(Action{ID: "go.link", Title: "Go to Linked Packet", Menu: "Go", Group: 1, Keys: []string{"ctrl+]"}, Ctx: ctxCapture, Run: (*App).gotoLinked, Enabled: cap})
	A(Action{ID: "go.nextconv", Title: "Next Packet in Conversation", Menu: "Go", Group: 1, Keys: []string{">"}, Ctx: ctxCapture, Run: func(m *App) tea.Cmd { return m.convStep(1) }, Enabled: cap})
	A(Action{ID: "go.prevconv", Title: "Previous Packet in Conversation", Menu: "Go", Group: 1, Keys: []string{"<"}, Ctx: ctxCapture, Run: func(m *App) tea.Cmd { return m.convStep(-1) }, Enabled: cap})
	A(Action{ID: "go.first", Title: "First Packet", Menu: "Go", Group: 2, Keys: []string{"home", "g"}, Ctx: ctxList, Run: func(m *App) tea.Cmd { return m.listMoveTo(0) }, Enabled: cap})
	A(Action{ID: "go.last", Title: "Last Packet", Menu: "Go", Group: 2, Keys: []string{"end", "G"}, Ctx: ctxList, Run: func(m *App) tea.Cmd { return m.listMoveTo(len(m.displayed) - 1) }, Enabled: cap})
	A(Action{ID: "go.autoscroll", Title: "Auto Scroll in Live Capture", Menu: "Go", Group: 3, Ctx: ctxCapture, Run: (*App).toggleAutoScroll, Enabled: cap})

	// ---- Capture ----
	A(Action{ID: "cap.toggle", Title: "Start/Stop Capture", Menu: "Capture", Keys: []string{"c", "ctrl+e"}, Hint: "capture", Ctx: ctxCapture | ctxStart, Run: (*App).toggleCapture})
	A(Action{ID: "cap.options", Title: "Options…", Menu: "Capture", Keys: []string{"K"}, Ctx: ctxGlobal | ctxStart, Run: (*App).captureOptionsDialog})
	A(Action{ID: "cap.restart", Title: "Restart", Menu: "Capture", Ctx: ctxCapture, Run: (*App).restartCapture, Enabled: func(m *App) bool { return m.capt.live != nil }})
	A(Action{ID: "cap.filter", Title: "Capture Filter…", Menu: "Capture", Group: 1, Ctx: ctxGlobal | ctxStart, Run: (*App).captureFilterDialog})
	A(Action{ID: "cap.extcap", Title: "Capture via extcap…", Menu: "Capture", Group: 1, Keys: []string{"X"}, Ctx: ctxGlobal | ctxStart, Run: (*App).extcapDialog})
	A(Action{ID: "cap.ssh", Title: "Capture via SSH…", Menu: "Capture", Group: 1, Keys: []string{"S"}, Ctx: ctxGlobal | ctxStart, Run: (*App).sshDialog})
	A(Action{ID: "cap.replay", Title: "Replay File as Live Capture…", Menu: "Capture", Group: 1, Ctx: ctxGlobal | ctxStart, Run: (*App).replayDialog})
	A(Action{ID: "cap.refresh", Title: "Refresh Interfaces", Menu: "Capture", Group: 2, Keys: []string{"f5"}, Ctx: ctxGlobal | ctxStart, Run: func(m *App) tea.Cmd { m.refreshIfaces(); return nil }})
	A(Action{ID: "cap.doctor", Title: "Check Capture Permissions…", Menu: "Capture", Group: 2, Ctx: ctxGlobal | ctxStart, Run: (*App).doctorDialog})

	// ---- Analyze ----
	A(Action{ID: "an.filter", Title: "Display Filter…", Menu: "Analyze", Keys: []string{"/"}, Hint: "filter", Ctx: ctxCapture, Run: (*App).focusFilter, Enabled: cap})
	A(Action{ID: "an.saved", Title: "Saved Display Filters…", Menu: "Analyze", Keys: []string{"F"}, Ctx: ctxCapture, Run: (*App).savedFiltersDialog, Enabled: cap})
	A(Action{ID: "an.clearfilter", Title: "Clear Display Filter", Menu: "Analyze", Keys: []string{"ctrl+x"}, Ctx: ctxCapture, Run: func(m *App) tea.Cmd { return m.applyFilter("") }, Enabled: cap})
	A(Action{ID: "an.apply", Title: "Apply as Filter…", Menu: "Analyze", Group: 1, Keys: []string{"a"}, Hint: "apply filter", Ctx: ctxDetails, Run: func(m *App) tea.Cmd { return m.filterFromFieldMenu(true) }, Enabled: cap})
	A(Action{ID: "an.prepare", Title: "Prepare as Filter…", Menu: "Analyze", Group: 1, Keys: []string{"p"}, Ctx: ctxDetails, Run: func(m *App) tea.Cmd { return m.filterFromFieldMenu(false) }, Enabled: cap})
	A(Action{ID: "an.column", Title: "Apply as Column", Menu: "Analyze", Group: 1, Keys: []string{"A"}, Ctx: ctxDetails, Run: (*App).applyAsColumn, Enabled: cap})
	A(Action{ID: "an.convfilter", Title: "Conversation Filter…", Menu: "Analyze", Group: 2, Ctx: ctxCapture, Run: (*App).conversationFilterMenu, Enabled: cap})
	A(Action{ID: "an.follow", Title: "Follow Stream", Menu: "Analyze", Group: 3, Keys: []string{"f"}, Hint: "follow", Ctx: ctxList | ctxDetails | ctxBytes, Run: func(m *App) tea.Cmd { return m.followSelected(0) }, Enabled: cap})
	A(Action{ID: "an.followtcp", Title: "Follow TCP Stream", Menu: "Analyze", Group: 3, Ctx: ctxCapture, Run: func(m *App) tea.Cmd { return m.followSelected(1) }, Enabled: cap})
	A(Action{ID: "an.followtls", Title: "Follow TLS Stream", Menu: "Analyze", Group: 3, Ctx: ctxCapture, Run: func(m *App) tea.Cmd { return m.followSelected(3) }, Enabled: cap})
	A(Action{ID: "an.followhttp", Title: "Follow HTTP Stream", Menu: "Analyze", Group: 3, Ctx: ctxCapture, Run: func(m *App) tea.Cmd { return m.followSelected(4) }, Enabled: cap})
	A(Action{ID: "an.decodeas", Title: "Decode As…", Menu: "Analyze", Group: 5, Ctx: ctxList | ctxDetails | ctxBytes | ctxGlobal, Run: (*App).decodeAsDialog})
	A(Action{ID: "an.enabled", Title: "Enabled Protocols…", Menu: "Analyze", Group: 5, Ctx: ctxGlobal | ctxCapture, Run: (*App).enabledProtocolsDialog})
	A(Action{ID: "an.buttons", Title: "Display Filter Buttons…", Menu: "Analyze", Group: 2, Keys: []string{"B"}, Ctx: ctxGlobal | ctxCapture, Run: (*App).filterButtonsDialog})
	A(Action{ID: "an.expression", Title: "Display Filter Expression…", Menu: "Analyze", Group: 2, Ctx: ctxGlobal | ctxCapture, Run: (*App).expressionDialog})
	A(Action{ID: "edit.timeshift", Title: "Time Shift…", Menu: "Edit", Group: 4, Ctx: ctxCapture, Run: (*App).timeShiftDialog, Enabled: cap})
	A(Action{ID: "edit.profiles", Title: "Configuration Profiles…", Menu: "Edit", Group: 9, Ctx: ctxGlobal | ctxStart | ctxCapture, Run: (*App).profilesDialog})
	A(Action{ID: "tools.lua", Title: "Lua Plugins…", Menu: "Tools", Ctx: ctxGlobal | ctxStart | ctxCapture, Run: (*App).luaPluginsDialog})
	A(Action{ID: "tools.firewall", Title: "Firewall ACL Rules…", Menu: "Tools", Ctx: ctxCapture, Run: (*App).firewallDialog, Enabled: cap})
	A(Action{ID: "an.deep", Title: "Deep Dissection (Wireshark)", Menu: "Analyze", Group: 5, Keys: []string{"D"}, Ctx: ctxList | ctxDetails | ctxBytes, Run: (*App).openDeepFrame, Enabled: cap})
	A(Action{ID: "an.followudp", Title: "Follow UDP Stream", Menu: "Analyze", Group: 3, Ctx: ctxCapture, Run: func(m *App) tea.Cmd { return m.followSelected(2) }, Enabled: cap})
	A(Action{ID: "an.expert", Title: "Expert Information", Menu: "Analyze", Group: 4, Keys: []string{"!"}, Ctx: ctxCapture, Run: (*App).openExpert, Enabled: cap})
	A(Action{ID: "an.ctx", Title: "Context Menu", Keys: []string{"."}, Hint: "menu", Ctx: ctxCapture, Run: (*App).contextMenu, Enabled: cap})

	// ---- Tools / Help ----
	A(Action{ID: "stat.conv", Title: "Conversations", Menu: "Statistics", Group: 1, Keys: []string{"ctrl+t"}, Ctx: ctxCapture, Run: (*App).openConversations, Enabled: cap})
	A(Action{ID: "stat.endpoints", Title: "Endpoints", Menu: "Statistics", Group: 1, Ctx: ctxCapture, Run: (*App).openEndpoints, Enabled: cap})
	A(Action{ID: "stat.phs", Title: "Protocol Hierarchy", Menu: "Statistics", Group: 1, Ctx: ctxCapture, Run: (*App).openHierarchy, Enabled: cap})
	A(Action{ID: "stat.io", Title: "I/O Graph", Menu: "Statistics", Group: 2, Ctx: ctxCapture, Run: (*App).openIOGraph, Enabled: cap})
	A(Action{ID: "stat.tcpgraph", Title: "TCP Stream Graphs", Menu: "Statistics", Group: 2, Ctx: ctxCapture, Run: (*App).openTCPGraph, Enabled: cap})
	A(Action{ID: "stat.flow", Title: "Flow Graph", Menu: "Statistics", Group: 2, Ctx: ctxCapture, Run: (*App).openFlowGraph, Enabled: cap})
	A(Action{ID: "stat.http", Title: "HTTP", Menu: "Statistics", Group: 3, Ctx: ctxCapture, Run: (*App).openHTTPStats, Enabled: cap})
	A(Action{ID: "stat.dns", Title: "DNS", Menu: "Statistics", Group: 3, Ctx: ctxCapture, Run: (*App).openDNSStats, Enabled: cap})
	A(Action{ID: "stat.deeptap", Title: "Wireshark Tap (deep)…", Menu: "Statistics", Group: 4, Ctx: ctxCapture, Run: (*App).deepTapDialog, Enabled: cap})
	A(Action{ID: "stat.len", Title: "Packet Lengths", Menu: "Statistics", Group: 1, Ctx: ctxCapture, Run: (*App).openPacketLengths, Enabled: cap})
	A(Action{ID: "tools.creds", Title: "Credentials", Menu: "Tools", Ctx: ctxCapture, Run: (*App).openCredentials, Enabled: cap})
	A(Action{ID: "tel.voip", Title: "VoIP Calls", Menu: "Telephony", Ctx: ctxCapture, Run: (*App).openVoIPCalls, Enabled: cap})
	A(Action{ID: "tel.rtp", Title: "RTP Streams", Menu: "Telephony", Ctx: ctxCapture, Run: (*App).openRTPStreams, Enabled: cap})
	A(Action{ID: "wl.traffic", Title: "WLAN Traffic", Menu: "Wireless", Ctx: ctxCapture, Run: (*App).openWLANTraffic, Enabled: cap})
	A(Action{ID: "tools.fields", Title: "Display Filter Field Reference…", Menu: "Tools", Ctx: ctxGlobal | ctxStart, Run: (*App).fieldReference})
	A(Action{ID: "help.keys", Title: "Keyboard Shortcuts", Menu: "Help", Keys: []string{"?", "f1"}, Hint: "help", Ctx: ctxGlobal | ctxStart, Run: (*App).helpDialog})
	A(Action{ID: "help.palette", Title: "Command Palette", Menu: "Help", Keys: []string{"ctrl+p", "ctrl+space"}, Hint: "commands", Ctx: ctxGlobal | ctxStart, Run: (*App).openPalette})
	A(Action{ID: "help.menu", Title: "Menu Bar", Keys: []string{"f10", "alt+m"}, Ctx: ctxGlobal | ctxStart, Run: (*App).openMenuBar})
	A(Action{ID: "help.about", Title: "About lazysniffer", Menu: "Help", Ctx: ctxGlobal | ctxStart, Run: (*App).aboutDialog})

	// Keys from the config override defaults.
	for _, a := range m.actions {
		if keys, ok := m.cfg.Keys[a.ID]; ok {
			a.Keys = keys
		}
	}
}

func (m *App) action(id string) *Action {
	for _, a := range m.actions {
		if a.ID == id {
			return a
		}
	}
	return nil
}

func (m *App) enabled(a *Action) bool { return a.Enabled == nil || a.Enabled(m) }

// currentCtx is the binding context of the focused pane.
func (m *App) currentCtx() ctx {
	if m.cap == nil {
		return ctxStart
	}
	switch m.focus {
	case paneDetails:
		return ctxDetails
	case paneBytes:
		return ctxBytes
	}
	return ctxList
}

// findAction returns the action bound to key in the current context.
// Pane-specific bindings win over global ones.
func (m *App) findAction(key string) *Action {
	c := m.currentCtx()
	var global *Action
	for _, a := range m.actions {
		for _, k := range a.Keys {
			if k != key {
				continue
			}
			if a.Ctx&c != 0 && a.Ctx&ctxGlobal == 0 {
				if m.enabled(a) {
					return a
				}
			}
			if a.Ctx&(ctxGlobal) != 0 && (c != ctxStart || a.Ctx&ctxStart != 0) && global == nil && m.enabled(a) {
				global = a
			}
		}
	}
	return global
}

// keyLabel renders the first key binding of an action for menus.
func keyLabel(a *Action) string {
	if len(a.Keys) == 0 {
		return ""
	}
	k := a.Keys[0]
	r := strings.NewReplacer("ctrl+", "^", "alt+", "M-", "shift+", "S-")
	return r.Replace(k)
}
