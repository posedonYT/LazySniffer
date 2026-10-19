package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/poseydon/lazysniffer/internal/export"
	"github.com/poseydon/lazysniffer/internal/keylog"
	"github.com/poseydon/lazysniffer/internal/pcaptools"
	"github.com/poseydon/lazysniffer/internal/resolve"
)

// keylogDialog edits the TLS key log file preference.
func (m *App) keylogDialog() tea.Cmd {
	d := newInput("TLS Key Log File", "SSLKEYLOGFILE-format file used to decrypt TLS and QUIC:", m.cfg.TLSKeylogFile, func(m *App, v string) tea.Cmd {
		v = expandHome(strings.TrimSpace(v))
		if v != "" {
			if _, err := os.Stat(v); err != nil {
				return m.setFlash(true, "%v", err)
			}
		}
		m.cfg.TLSKeylogFile = v
		_ = m.cfg.Save()
		files := []string{v}
		if env := os.Getenv("SSLKEYLOGFILE"); env != "" && env != v {
			files = append(files, env)
		}
		keylog.Default.SetFiles(files...)
		msg := fmt.Sprintf("TLS key log: %d connection(s) with secrets", keylog.Default.Count())
		if m.cap != nil {
			return tea.Batch(m.reload(), m.setFlash(false, "%s", msg))
		}
		return m.setFlash(false, "%s", msg)
	})
	d.complete = completePath
	d.help = []string{
		"Start a browser or curl with SSLKEYLOGFILE=/path/to/keys.log, capture, then point lazysniffer at that file.",
		"Keys embedded in a pcapng (Decryption Secrets Block) are used automatically.",
	}
	return m.push(d)
}

// exportKeysDialog writes the known TLS secrets to a key log file.
func (m *App) exportKeysDialog() tea.Cmd {
	if keylog.Default.Count() == 0 {
		return m.setFlash(true, "No TLS secrets are loaded")
	}
	return m.push(newInput("Export TLS Session Keys", fmt.Sprintf("%d connection(s) → key log file:", keylog.Default.Count()), "tls-keys.log", func(m *App, v string) tea.Cmd {
		path := expandHome(strings.TrimSpace(v))
		if err := os.WriteFile(path, keylog.Default.Export(), 0o600); err != nil {
			return m.setFlash(true, "%v", err)
		}
		return m.setFlash(false, "Wrote TLS keys to %s", path)
	}))
}

// saveWithKeys saves the capture with the TLS secrets embedded (pcapng DSB).
func (m *App) saveWithKeys() tea.Cmd {
	if keylog.Default.Count() == 0 {
		return m.setFlash(true, "No TLS secrets are loaded")
	}
	export.EmbedKeys = true
	return m.saveAsDialog()
}

var lastKeyReload time.Time

// checkKeylog re-dissects the capture when the key log file grew (live
// captures write secrets after the handshake was already captured).
func (m *App) checkKeylog() tea.Cmd {
	if m.cap == nil || m.loading || time.Since(lastKeyReload) < 3*time.Second {
		return nil
	}
	if !keylog.Default.Reload() {
		return nil
	}
	lastKeyReload = time.Now()
	return m.openFileWith(m.cap.Path, m.cap.Live)
}

// exportDissectionsDialog writes the displayed packets as text, CSV, JSON,
// PSML or PDML (chosen by the file extension).
func (m *App) exportDissectionsDialog() tea.Cmd {
	frames := m.displayed
	if len(frames) == 0 && m.cap.Count() > 0 {
		for i := 1; i <= m.cap.Count(); i++ {
			frames = append(frames, uint32(i))
		}
	}
	def := strings.TrimSuffix(m.cap.Path, filepath.Ext(m.cap.Path)) + ".csv"
	d := newInput("Export Packet Dissections", fmt.Sprintf("%s packets → file (.txt .log .csv .json .psml .pdml):", commas(len(frames))), def, func(m *App, v string) tea.Cmd {
		path := expandHome(strings.TrimSpace(v))
		f, err := os.Create(path)
		if err != nil {
			return m.setFlash(true, "%v", err)
		}
		defer f.Close()
		if err := export.WriteDissections(context.Background(), f, m.cap, frames, export.DissectFormatFromPath(path)); err != nil {
			return m.setFlash(true, "Export failed: %v", err)
		}
		return m.setFlash(false, "Exported %s packets to %s", commas(len(frames)), path)
	})
	d.complete = completePath
	return m.push(d)
}

// geoipDialog sets the folder with MaxMind GeoLite2 databases.
func (m *App) geoipDialog() tea.Cmd {
	d := newInput("GeoIP Database Folder", "Folder with GeoLite2-Country/City/ASN .mmdb files:", m.cfg.GeoIPDir, func(m *App, v string) tea.Cmd {
		v = expandHome(strings.TrimSpace(v))
		loaded := resolve.LoadGeoIP(v)
		if v != "" && len(loaded) == 0 {
			return m.setFlash(true, "No GeoLite2 .mmdb files found in %s", v)
		}
		m.cfg.GeoIPDir = v
		_ = m.cfg.Save()
		return m.setFlash(false, "GeoIP loaded: %s", strings.Join(loaded, ", "))
	})
	d.complete = completePath
	d.help = []string{"Free GeoLite2 databases: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data", "Endpoints then shows country, city and AS."}
	return m.push(d)
}

// mergeDialog merges another capture file into the open one.
func (m *App) mergeDialog() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	d := newInput("Merge With File", "Capture file to merge chronologically with the open capture:", "", func(m *App, v string) tea.Cmd {
		other := expandHome(strings.TrimSpace(v))
		pk, secrets, err := pcaptools.Merge([]string{m.cap.Path, other}, false)
		if err != nil {
			return m.setFlash(true, "%v", err)
		}
		tmp, err := os.CreateTemp("", "lazysniffer-merge-*.pcapng")
		if err != nil {
			return m.setFlash(true, "%v", err)
		}
		defer tmp.Close()
		if err := pcaptools.Write(tmp, pk, pcaptools.WriteOptions{Secrets: secrets}); err != nil {
			return m.setFlash(true, "%v", err)
		}
		return m.openFile(tmp.Name())
	})
	d.complete = completePath
	return m.push(d)
}
