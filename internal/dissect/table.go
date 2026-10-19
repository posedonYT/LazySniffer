package dissect

import (
	"sort"
	"sync"
)

// DissectFunc dissects tvb and returns the number of bytes consumed. A
// heuristic or port-based dissector returns 0 to reject the data.
type DissectFunc func(tvb *Tvb, pi *PacketInfo, tree *Node) int

// Handle is a callable dissector.
type Handle struct {
	Name  string
	Proto *Proto
	Fn    DissectFunc
}

// NewHandle creates a dissector handle for p.
func NewHandle(p *Proto, fn DissectFunc) *Handle {
	name := ""
	if p != nil {
		name = p.Filter
	}
	return &Handle{Name: name, Proto: p, Fn: fn}
}

var (
	handlesMu sync.RWMutex
	handles   = map[string]*Handle{}
)

// RegisterHandle makes a handle findable by name (Decode As, "data", ...).
func RegisterHandle(name string, h *Handle) *Handle {
	handlesMu.Lock()
	handles[name] = h
	handlesMu.Unlock()
	return h
}

// FindHandle returns a registered handle by name.
func FindHandle(name string) *Handle {
	handlesMu.RLock()
	defer handlesMu.RUnlock()
	return handles[name]
}

// UintTable dispatches on an integer key (ethertype, ip.proto, tcp.port...).
type UintTable struct {
	Name   string
	UIName string
	mu     sync.RWMutex
	m      map[uint64]*Handle
	user   map[uint64]*Handle // Decode As overrides
}

var (
	tablesMu sync.Mutex
	tables   = map[string]*UintTable{}
)

// Table returns the integer dissector table with the given name, creating it.
func Table(name string) *UintTable {
	tablesMu.Lock()
	defer tablesMu.Unlock()
	t := tables[name]
	if t == nil {
		t = &UintTable{Name: name, UIName: name, m: map[uint64]*Handle{}, user: map[uint64]*Handle{}}
		tables[name] = t
	}
	return t
}

// Tables lists all dissector tables.
func Tables() []*UintTable {
	tablesMu.Lock()
	defer tablesMu.Unlock()
	out := make([]*UintTable, 0, len(tables))
	for _, t := range tables {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Add registers h for key.
func (t *UintTable) Add(key uint64, h *Handle) {
	t.mu.Lock()
	t.m[key] = h
	t.mu.Unlock()
}

// SetUser installs a Decode As override (nil removes it).
func (t *UintTable) SetUser(key uint64, h *Handle) {
	t.mu.Lock()
	if h == nil {
		delete(t.user, key)
	} else {
		t.user[key] = h
	}
	t.mu.Unlock()
}

// Lookup returns the handle for key.
func (t *UintTable) Lookup(key uint64) *Handle {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if h, ok := t.user[key]; ok {
		return h
	}
	return t.m[key]
}

// Try dissects with the handle registered for key. It returns consumed
// bytes and whether a handle accepted the data.
func (t *UintTable) Try(key uint64, tvb *Tvb, pi *PacketInfo, tree *Node) (int, bool) {
	h := t.Lookup(key)
	if h == nil {
		return 0, false
	}
	saved := pi.MatchUint
	pi.MatchUint = key
	n := pi.Call(h, tvb, tree)
	pi.MatchUint = saved
	return n, n > 0
}

// Entries returns a snapshot of the table's registrations.
func (t *UintTable) Entries() map[uint64]*Handle {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[uint64]*Handle, len(t.m))
	for k, v := range t.m {
		out[k] = v
	}
	for k, v := range t.user {
		out[k] = v
	}
	return out
}

// HeurFunc returns true when it recognized and dissected the data.
type HeurFunc func(tvb *Tvb, pi *PacketInfo, tree *Node) bool

// HeurEntry is a heuristic dissector.
type HeurEntry struct {
	Name    string
	Proto   *Proto
	Fn      HeurFunc
	Enabled bool
}

// HeurList is a list of heuristic dissectors (e.g. "udp", "tcp").
type HeurList struct {
	Name    string
	mu      sync.RWMutex
	entries []*HeurEntry
}

var (
	heurMu sync.Mutex
	heurs  = map[string]*HeurList{}
)

// Heur returns the heuristic list with the given name.
func Heur(name string) *HeurList {
	heurMu.Lock()
	defer heurMu.Unlock()
	l := heurs[name]
	if l == nil {
		l = &HeurList{Name: name}
		heurs[name] = l
	}
	return l
}

// Add registers a heuristic dissector.
func (l *HeurList) Add(name string, p *Proto, fn HeurFunc) {
	l.mu.Lock()
	l.entries = append(l.entries, &HeurEntry{Name: name, Proto: p, Fn: fn, Enabled: true})
	l.mu.Unlock()
}

// Try runs heuristics in registration order until one accepts the data.
func (l *HeurList) Try(tvb *Tvb, pi *PacketInfo, tree *Node) bool {
	l.mu.RLock()
	entries := l.entries
	l.mu.RUnlock()
	for _, e := range entries {
		if !e.Enabled || (e.Proto != nil && !e.Proto.Enabled) {
			continue
		}
		ok := false
		pi.Call(&Handle{Proto: e.Proto, Fn: func(tvb *Tvb, pi *PacketInfo, tree *Node) int {
			if e.Fn(tvb, pi, tree) {
				ok = true
				return tvb.Len()
			}
			return 0
		}}, tvb, tree)
		if ok {
			return true
		}
	}
	return false
}

// HandleNames lists the registered handle names.
func HandleNames() []string {
	handlesMu.RLock()
	defer handlesMu.RUnlock()
	out := make([]string, 0, len(handles))
	for n := range handles {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// UserEntries returns the Decode As overrides of the table.
func (t *UintTable) UserEntries() map[uint64]*Handle {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[uint64]*Handle, len(t.user))
	for k, v := range t.user {
		out[k] = v
	}
	return out
}
