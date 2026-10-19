package ui

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/poseydon/lazysniffer/internal/stats"
)

var rtpCodecNames = map[uint8]string{0: "g711U", 3: "GSM", 4: "g723", 8: "g711A", 9: "g722", 18: "g729", 26: "JPEG", 31: "H261", 34: "H263"}

func codecName(pt uint8) string {
	if n := rtpCodecNames[pt]; n != "" {
		return n
	}
	return fmt.Sprintf("PT %d", pt)
}

// openRTPStreams shows Telephony → RTP Streams.
func (m *App) openRTPStreams() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	t := &tableTab{name: "RTP Streams", extra: [][2]string{{"enter", "go to first packet"}, {"a", "apply as filter"}, {"w", "save audio (.wav)"}, {"P", "play audio"}}}
	var streams []*stats.RTPStream
	build := func(m *App, t *tableTab) error {
		var err error
		streams, err = stats.RTPStreams(context.Background(), m.cap)
		if err != nil {
			return err
		}
		set := &tableSet{name: "Streams", cols: []tcol{{"Source", 0, false}, {"Destination", 0, false}, {"SSRC", 11, false}, {"Codec", 8, false}, {"Packets", 8, true},
			{"Lost", 14, true}, {"Seq err", 8, true}, {"Max delta", 10, true}, {"Mean jitter", 11, true}, {"Max jitter", 10, true}, {"Start", 9, true}, {"Problem", 7, false}}}
		for i, s := range streams {
			prob := ""
			if s.Lost > 0 || s.SeqErrors > 0 {
				prob = "X"
			}
			set.rows = append(set.rows, trow{frame: s.First, data: i, filter: s.Filter(), keys: []float64{0, 0, float64(s.SSRC), float64(s.PayloadType), float64(s.Packets),
				float64(s.Lost), float64(s.SeqErrors), s.MaxDelta, s.MeanJitter, s.MaxJitter, s.Start},
				cells: []string{s.Src, s.Dst, fmt.Sprintf("0x%08x", s.SSRC), codecName(s.PayloadType), commas(s.Packets),
					fmt.Sprintf("%d (%.1f%%)", s.Lost, s.LostPct()), fmt.Sprint(s.SeqErrors), fmt.Sprintf("%.2f ms", s.MaxDelta), fmt.Sprintf("%.2f ms", s.MeanJitter),
					fmt.Sprintf("%.2f ms", s.MaxJitter), fmt.Sprintf("%.3f", s.Start), prob}})
		}
		set.foot = fmt.Sprintf("%d RTP stream(s)", len(streams))
		t.sets = []*tableSet{set}
		return nil
	}
	t.refresh = build
	t.onKey = func(m *App, t *tableTab, row *trow, key string) (tea.Cmd, bool) {
		if row == nil {
			return nil, false
		}
		s := streams[row.data.(int)]
		switch key {
		case "w":
			def := filepath.Join(downloadDir(), fmt.Sprintf("rtp-0x%08x.wav", s.SSRC))
			return m.push(newInput("Save RTP audio", "Decoded G.711 audio → .wav file:", def, func(m *App, v string) tea.Cmd {
				path := expandHome(strings.TrimSpace(v))
				if err := saveRTPWav(m, s, path); err != nil {
					return m.setFlash(true, "%v", err)
				}
				return m.setFlash(false, "Saved %s", path)
			})), true
		case "P":
			return m.playRTP(s), true
		}
		return nil, false
	}
	if err := build(m, t); err != nil {
		return m.setFlash(true, "RTP: %v", err)
	}
	m.openUniqueTab(t)
	if len(streams) == 0 {
		return m.setFlash(false, "No RTP streams (RTP is recognised after SIP/SDP set up the media ports)")
	}
	return nil
}

func saveRTPWav(m *App, s *stats.RTPStream, path string) error {
	pcm, err := stats.RTPAudio(context.Background(), m.cap, s)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := stats.WriteWAV(&buf, pcm, 8000); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// playRTP decodes the stream to a temporary WAV and plays it with the
// system audio player (afplay, paplay or aplay).
func (m *App) playRTP(s *stats.RTPStream) tea.Cmd {
	player := ""
	for _, p := range []string{"afplay", "paplay", "aplay", "play"} {
		if path, err := exec.LookPath(p); err == nil {
			player = path
			break
		}
	}
	if player == "" {
		return m.setFlash(true, "No audio player found (afplay, paplay, aplay); use w to save a .wav file")
	}
	f, err := os.CreateTemp("", "lazysniffer-rtp-*.wav")
	if err != nil {
		return m.setFlash(true, "%v", err)
	}
	f.Close()
	if err := saveRTPWav(m, s, f.Name()); err != nil {
		os.Remove(f.Name())
		return m.setFlash(true, "%v", err)
	}
	go func() {
		exec.Command(player, f.Name()).Run()
		os.Remove(f.Name())
	}()
	return m.setFlash(false, "Playing 0x%08x (%.1f s)…", s.SSRC, s.Duration)
}

// openVoIPCalls shows Telephony → VoIP Calls.
func (m *App) openVoIPCalls() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	t := &tableTab{name: "VoIP Calls", extra: [][2]string{{"enter", "go to first packet"}, {"a", "filter the call"}, {"R", "RTP streams"}, {"F", "flow graph"}}}
	var calls []*stats.VoIPCall
	build := func(m *App, t *tableTab) error {
		var err error
		calls, err = stats.VoIPCalls(context.Background(), m.cap)
		if err != nil {
			return err
		}
		set := &tableSet{name: "Calls", cols: []tcol{{"Start", 9, true}, {"Duration", 9, true}, {"From", 0, false}, {"To", 0, false}, {"Protocol", 8, false}, {"Packets", 8, true}, {"RTP", 5, true}, {"State", 12, false}}}
		for i, c := range calls {
			pk := len(c.Frames)
			for _, s := range c.Streams {
				pk += s.Packets
			}
			set.rows = append(set.rows, trow{frame: c.First, data: i, filter: callFilter(c), keys: []float64{c.Start, c.Duration, 0, 0, 0, float64(pk), float64(len(c.Streams)), 0},
				cells: []string{fmt.Sprintf("%.3f", c.Start), fmt.Sprintf("%.3f", c.Duration), c.From, c.To, "SIP", commas(pk), fmt.Sprint(len(c.Streams)), c.State}})
		}
		set.foot = fmt.Sprintf("%d call(s)", len(calls))
		t.sets = []*tableSet{set}
		return nil
	}
	t.refresh = build
	t.onKey = func(m *App, t *tableTab, row *trow, key string) (tea.Cmd, bool) {
		if row == nil {
			return nil, false
		}
		c := calls[row.data.(int)]
		switch key {
		case "R":
			m.tab = -1
			return tea.Batch(m.applyFilter(callFilter(c)), m.openRTPStreams()), true
		case "F":
			m.tab = -1
			return tea.Batch(m.applyFilter(callFilter(c)), m.openFlowGraph()), true
		}
		return nil, false
	}
	if err := build(m, t); err != nil {
		return m.setFlash(true, "VoIP: %v", err)
	}
	m.openUniqueTab(t)
	if len(calls) == 0 {
		return m.setFlash(false, "No SIP calls found")
	}
	return nil
}

// callFilter selects the SIP messages and media of a call.
func callFilter(c *stats.VoIPCall) string {
	f := fmt.Sprintf("sip.Call-ID == %q", c.CallID)
	for _, s := range c.Streams {
		f += " || " + s.Filter()
	}
	return f
}

// openWLANTraffic shows Wireless → WLAN Traffic.
func (m *App) openWLANTraffic() tea.Cmd {
	if m.cap == nil {
		return nil
	}
	t := &tableTab{name: "WLAN Traffic", extra: [][2]string{{"a", "apply as filter"}, {"p", "prepare"}}}
	build := func(m *App, t *tableTab) error {
		nets, err := stats.WLANTraffic(context.Background(), m.cap)
		if err != nil {
			return err
		}
		set := &tableSet{name: "BSS", cols: []tcol{{"BSSID", 18, false}, {"SSID", 0, false}, {"Chan", 5, true}, {"Beacons", 8, true}, {"Data", 8, true}, {"Mgmt", 8, true},
			{"Ctrl", 7, true}, {"Retries", 8, true}, {"Packets", 9, true}, {"Signal dBm", 11, true}, {"Enc", 4, false}}}
		for _, n := range nets {
			sig := ""
			if n.SigMax > -200 && n.SigMin <= 0 {
				sig = fmt.Sprintf("%d…%d", n.SigMin, n.SigMax)
			}
			enc := ""
			if n.Encrypted {
				enc = "yes"
			}
			set.rows = append(set.rows, trow{filter: fmt.Sprintf("wlan.addr == %s", n.BSSID), frame: n.First,
				keys:  []float64{0, 0, float64(n.Channel), float64(n.Beacons), float64(n.Data), float64(n.Mgmt), float64(n.Control), float64(n.Retries), float64(n.Packets), float64(n.SigMax)},
				cells: []string{n.BSSID, n.SSID, fmt.Sprint(n.Channel), commas(n.Beacons), commas(n.Data), commas(n.Mgmt), commas(n.Control), commas(n.Retries), commas(n.Packets), sig, enc}})
		}
		set.sortCol, set.desc = 8, true
		set.sortRows()
		set.foot = fmt.Sprintf("%d BSS(s)", len(nets))
		t.sets = []*tableSet{set}
		return nil
	}
	t.refresh = build
	if err := build(m, t); err != nil {
		return m.setFlash(true, "WLAN: %v", err)
	}
	m.openUniqueTab(t)
	return nil
}
