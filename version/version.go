// Package version resolves a binary's build version, preferring an
// ldflags-injected value and otherwise deriving one from
// runtime/debug.BuildInfo — so `go install …@vX.Y.Z` and source-tree
// builds still report something useful without a Make-driven inject.
//
// Usage: keep `var Version = "dev"` in your main package (the linker
// target stays main.Version, so no -ldflags path changes) and call
// version.Resolve(Version).
package version

import (
	"runtime/debug"
	"time"
)

// devSentinel is the placeholder a binary's `var Version` carries until
// the linker overwrites it via -ldflags "-X main.Version=...".
const devSentinel = "dev"

// Resolve maps the ldflags-injected value (pass your package-level
// main.Version) to an effective version string, with the VCS commit time
// appended as " (<local time>)" whenever the toolchain recorded one.
//
// Base token, in order:
//
//  1. injected, when the linker set it to anything other than "dev"
//  2. BuildInfo.Main.Version when it's a real module version (e.g.
//     "v1.2.3") — what `go install pkg@vX.Y.Z` records
//  3. "dev-<vcs.revision[:7]>[-dirty]" from the VCS settings the
//     toolchain stamps into binaries built from a source tree
//  4. "dev" — last resort (e.g. `go run` outside a module)
//
// The commit time (vcs.time, rendered in the local zone; the toolchain
// stamps it as UTC) is appended to that token whenever it's present, so a
// binary reports when it was built on every path the toolchain records it.
// It's absent for `go install pkg@version` (no source tree) and
// -buildvcs=false builds, where the bare token is returned unchanged.
func Resolve(injected string) string {
	return resolve(injected, debug.ReadBuildInfo, time.Local)
}

// resolve is the testable core: readBuildInfo and loc are injected so
// tests can feed controlled BuildInfo and a fixed time zone instead of
// the real binary's.
func resolve(injected string, readBuildInfo func() (*debug.BuildInfo, bool), loc *time.Location) string {
	info, ok := readBuildInfo()
	if !ok {
		// No build info: only the injected value is available.
		return injected
	}

	var rev, dirty, vtime string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) >= 7 {
				rev = s.Value[:7]
			} else {
				rev = s.Value
			}
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		case "vcs.time":
			vtime = s.Value
		}
	}

	tok := injected
	if injected == devSentinel {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			tok = v
		} else if rev != "" {
			tok = "dev-" + rev + dirty
		}
	}

	if vtime != "" {
		tok += " (" + localTime(vtime, loc) + ")"
	}
	return tok
}

// localTime parses the toolchain's RFC3339/UTC vcs.time and renders it
// in loc. Falls back to the raw value if it doesn't parse.
func localTime(raw string, loc *time.Location) string {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return t.In(loc).Format(time.RFC3339)
}
