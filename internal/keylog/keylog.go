// Package keylog holds TLS secrets in the NSS key log format
// (SSLKEYLOGFILE) and looks them up by client random.
package keylog

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// Store is a set of key log entries.
type Store struct {
	mu    sync.RWMutex
	m     map[string]map[string][]byte // client random (hex) → label → secret
	gen   atomic.Uint64
	files map[string]fileState
	conf  []string // files that are re-read after Reset
}

type fileState struct {
	size int64
	mod  int64
}

// Default is the process-wide store used by the dissectors.
var Default = New()

func New() *Store { return &Store{m: map[string]map[string][]byte{}, files: map[string]fileState{}} }

// Reset removes all entries and watched files.
func (s *Store) Reset() {
	s.mu.Lock()
	s.m = map[string]map[string][]byte{}
	s.files = map[string]fileState{}
	conf := s.conf
	s.mu.Unlock()
	for _, p := range conf {
		_ = s.LoadFile(p)
	}
	s.gen.Add(1)
}

// SetFiles sets the key log files that are always loaded (preferences,
// --keylog, $SSLKEYLOGFILE) and loads them now.
func (s *Store) SetFiles(paths ...string) {
	s.mu.Lock()
	s.conf = nil
	for _, p := range paths {
		if p != "" {
			s.conf = append(s.conf, p)
		}
	}
	s.mu.Unlock()
	s.Reset()
}

// Files returns the configured key log files.
func (s *Store) Files() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.conf...)
}

// Generation increases whenever entries are added.
func (s *Store) Generation() uint64 { return s.gen.Load() }

// Count is the number of connections with at least one secret.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// AddLine parses one key log line; it reports whether it was valid.
func (s *Store) AddLine(line string) bool {
	f := strings.Fields(line)
	if len(f) != 3 || strings.HasPrefix(f[0], "#") {
		return false
	}
	cr, err1 := hex.DecodeString(f[1])
	sec, err2 := hex.DecodeString(f[2])
	if err1 != nil || err2 != nil || len(cr) == 0 || len(sec) == 0 {
		return false
	}
	k := f[1]
	s.mu.Lock()
	if s.m[k] == nil {
		s.m[k] = map[string][]byte{}
	}
	changed := s.m[k][f[0]] == nil
	s.m[k][f[0]] = sec
	s.mu.Unlock()
	if changed {
		s.gen.Add(1)
	}
	return true
}

// AddData adds every line of data (a file or a pcapng DSB).
func (s *Store) AddData(data []byte) int {
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		if s.AddLine(sc.Text()) {
			n++
		}
	}
	return n
}

// LoadFile reads a key log file and remembers it for Reload.
func (s *Store) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	st, _ := os.Stat(path)
	s.AddData(data)
	s.mu.Lock()
	if st != nil {
		s.files[path] = fileState{st.Size(), st.ModTime().UnixNano()}
	}
	s.mu.Unlock()
	return nil
}

// Reload re-reads watched files that changed and reports whether new
// secrets appeared.
func (s *Store) Reload() bool {
	s.mu.RLock()
	paths := make([]string, 0, len(s.files))
	for p, st := range s.files {
		if fi, err := os.Stat(p); err == nil && (fi.Size() != st.size || fi.ModTime().UnixNano() != st.mod) {
			paths = append(paths, p)
		}
	}
	s.mu.RUnlock()
	before := s.gen.Load()
	for _, p := range paths {
		s.LoadFile(p)
	}
	return s.gen.Load() != before
}

// Lookup returns the secret for a label and client random, or nil.
func (s *Store) Lookup(clientRandom []byte, label string) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[hex.EncodeToString(clientRandom)][label]
}

// Export returns all entries in key log format.
func (s *Store) Export() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var b bytes.Buffer
	for cr, labels := range s.m {
		for l, sec := range labels {
			b.WriteString(l + " " + cr + " " + hex.EncodeToString(sec) + "\n")
		}
	}
	return b.Bytes()
}
