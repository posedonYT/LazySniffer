package ui

import (
	tea "charm.land/bubbletea/v2"
)

func (m *App) onClick(ms tea.Mouse) tea.Cmd {
	x, y := ms.X, ms.Y
	// Clicks outside an open popup close it.
	if len(m.dialogs) > 0 {
		if ms.Button == tea.MouseRight {
			m.pop()
		}
		return nil
	}
	if m.palette != nil {
		m.palette = nil
		return nil
	}
	if m.menuOpen >= 0 {
		if y == 0 {
			return m.clickMenuBar(x)
		}
		m.menuOpen = -1
		return nil
	}
	if y == 0 {
		return m.clickMenuBar(x)
	}
	if m.cap == nil {
		return nil
	}
	if m.rFilter.contains(x, y) {
		return m.focusFilter()
	}
	if len(m.tabs) > 0 && y == 2 {
		m.clickTabBar(x)
		return nil
	}
	if m.currentTab() != nil {
		return nil
	}
	switch {
	case m.rList.w > 0 && m.rList.contains(x, y):
		if m.focus == paneFilter {
			m.setFocus(paneList)
		}
		m.setFocus(paneList)
		row := y - m.rList.y - 2
		if row >= 0 {
			idx := m.list.offset + row
			if idx < len(m.displayed) {
				m.selectIndex(idx)
			}
		}
		if ms.Button == tea.MouseRight {
			return m.contextMenu()
		}
	case m.rDetails.w > 0 && m.rDetails.contains(x, y):
		m.setFocus(paneDetails)
		row := y - m.rDetails.y - 1
		idx := m.details.offset + row
		if row >= 0 && idx < len(m.details.items) {
			wasSelected := idx == m.details.cursor
			m.details.cursor = idx
			cur := m.details.current()
			m.details.selKey = nodeKey(cur)
			m.bytes.syncToNode(m)
			if ms.Button == tea.MouseRight {
				return m.contextMenu()
			}
			// Clicking the expander (or a selected item) toggles it.
			col := x - m.rDetails.x - 1
			depth := m.details.items[idx].depth
			if cur.HasChildren() && (wasSelected || col >= depth*2 && col < depth*2+2) {
				m.details.setExpanded(cur, !m.details.expanded[nodeKey(cur)])
			} else if wasSelected && cur.Link != 0 {
				return m.gotoFrame(cur.Link)
			}
		}
	case m.rBytes.w > 0 && m.rBytes.contains(x, y):
		m.setFocus(paneBytes)
		hs := &m.bytes
		row := y - m.rBytes.y - 1
		if m.selPI != nil && len(m.selPI.Sources) > 1 {
			row--
		}
		col := x - m.rBytes.x - 1 - 6
		if row < 0 || col < 0 || hs.perLine == 0 {
			return nil
		}
		var i int
		if hs.bits {
			i = col / 9
		} else {
			if col >= 8*3+1 {
				col--
			}
			i = col / 3
		}
		if i >= hs.perLine {
			// Click in the ASCII column.
			asc := x - m.rBytes.x - 1 - 6 - hs.perLine*3 - 2
			i = asc
		}
		if i >= 0 && i < hs.perLine {
			off := (hs.offset+row)*hs.perLine + i
			if off < len(m.sourceData()) {
				hs.cursor = off
				m.selectNodeAtByte(hs.ds, off)
			}
		}
	}
	return nil
}

func (m *App) clickMenuBar(x int) tea.Cmd {
	for i := len(m.menuX) - 1; i >= 0; i-- {
		if m.menuX[i] >= 0 && x >= m.menuX[i] {
			if m.menuOpen == i {
				m.menuOpen = -1
			} else {
				m.openMenu(i)
			}
			return nil
		}
	}
	return nil
}

func (m *App) onWheel(ms tea.Mouse) tea.Cmd {
	if len(m.dialogs) > 0 || m.palette != nil || m.menuOpen >= 0 || m.cap == nil {
		return nil
	}
	d := 3
	if ms.Button == tea.MouseWheelUp {
		d = -3
	} else if ms.Button != tea.MouseWheelDown {
		return nil
	}
	switch {
	case m.rDetails.w > 0 && m.rDetails.contains(ms.X, ms.Y):
		m.details.offset = max(m.details.offset+d, 0)
		m.details.cursor = max(min(m.details.cursor+d, len(m.details.items)-1), 0)
		m.bytes.syncToNode(m)
	case m.rBytes.w > 0 && m.rBytes.contains(ms.X, ms.Y):
		m.bytes.offset = max(m.bytes.offset+d, 0)
	default:
		n := len(m.displayed)
		if n > 0 {
			m.selectIndex(max(min(m.list.cursor+d, n-1), 0))
		}
	}
	return nil
}
