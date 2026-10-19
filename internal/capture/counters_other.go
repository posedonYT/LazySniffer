//go:build !darwin && !linux

package capture

func readCounters() map[string]Counters { return map[string]Counters{} }
