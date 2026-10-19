// Package version holds build information set by the linker.
package version

import "runtime/debug"

// Version is overridden at build time with -ldflags "-X ...version.Version=v1.2.3".
var Version = "dev"

// String returns the version with the VCS revision when known.
func String() string {
	v := Version
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				v += " (" + s.Value[:7] + ")"
			}
		}
	}
	return v
}
