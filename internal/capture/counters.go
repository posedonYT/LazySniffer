package capture

// Counters are an interface's cumulative traffic counters.
type Counters struct {
	Packets uint64
	Bytes   uint64
}

// ReadCounters returns per-interface counters without capture privileges
// (used for the activity sparklines on the start screen).
func ReadCounters() map[string]Counters { return readCounters() }
