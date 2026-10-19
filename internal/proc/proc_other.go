//go:build !linux

package proc

// Supported reports whether socket sampling works on this platform.
const Supported = false

// Sample is a no-op outside Linux.
func (t *Table) Sample() error { return nil }
