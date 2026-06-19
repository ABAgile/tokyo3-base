package version

import (
	"runtime/debug"
	"testing"
	"time"
)

// bi builds a readBuildInfo func returning the given main version and
// settings (ok=true).
func bi(mainVer string, settings ...debug.BuildSetting) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Main: debug.Module{Version: mainVer}, Settings: settings}, true
	}
}

func TestResolve(t *testing.T) {
	// Fixed +08:00 zone so local-rendered timestamps are deterministic
	// regardless of where the test runs.
	tz := time.FixedZone("UTC+8", 8*3600)
	tests := []struct {
		name     string
		injected string
		read     func() (*debug.BuildInfo, bool)
		want     string
	}{
		{"ldflags wins", "v1.2.3", bi("ignored"), "v1.2.3"},
		{"injected dev-sha passes through", "dev-abc1234", bi("ignored"), "dev-abc1234"},
		{"no build info", "dev", func() (*debug.BuildInfo, bool) { return nil, false }, "dev"},
		{"module version", "dev", bi("v2.0.0"), "v2.0.0"},
		{"vcs revision", "dev", bi("(devel)",
			debug.BuildSetting{Key: "vcs.revision", Value: "abcdef1234567890"}), "dev-abcdef1"},
		{"vcs revision dirty", "dev", bi("(devel)",
			debug.BuildSetting{Key: "vcs.revision", Value: "abcdef1234567890"},
			debug.BuildSetting{Key: "vcs.modified", Value: "true"}), "dev-abcdef1-dirty"},
		{"vcs revision with time rendered local", "dev", bi("(devel)",
			debug.BuildSetting{Key: "vcs.revision", Value: "abcdef1234567890"},
			debug.BuildSetting{Key: "vcs.time", Value: "2026-05-31T09:30:00Z"}),
			"dev-abcdef1 (2026-05-31T17:30:00+08:00)"},
		{"vcs revision dirty with time rendered local", "dev", bi("(devel)",
			debug.BuildSetting{Key: "vcs.revision", Value: "abcdef1234567890"},
			debug.BuildSetting{Key: "vcs.modified", Value: "true"},
			debug.BuildSetting{Key: "vcs.time", Value: "2026-05-31T09:30:00Z"}),
			"dev-abcdef1-dirty (2026-05-31T17:30:00+08:00)"},
		{"unparseable time falls back to raw", "dev", bi("(devel)",
			debug.BuildSetting{Key: "vcs.revision", Value: "abcdef1234567890"},
			debug.BuildSetting{Key: "vcs.time", Value: "not-a-timestamp"}),
			"dev-abcdef1 (not-a-timestamp)"},
		{"injected token gains time", "v1.2.3", bi("ignored",
			debug.BuildSetting{Key: "vcs.time", Value: "2026-05-31T09:30:00Z"}),
			"v1.2.3 (2026-05-31T17:30:00+08:00)"},
		{"module version gains time", "dev", bi("v2.0.0",
			debug.BuildSetting{Key: "vcs.time", Value: "2026-05-31T09:30:00Z"}),
			"v2.0.0 (2026-05-31T17:30:00+08:00)"},
		{"time without revision still shown", "dev", bi("(devel)",
			debug.BuildSetting{Key: "vcs.time", Value: "2026-05-31T09:30:00Z"}),
			"dev (2026-05-31T17:30:00+08:00)"},
		{"short revision used whole", "dev", bi("(devel)",
			debug.BuildSetting{Key: "vcs.revision", Value: "abc"}), "dev-abc"},
		{"devel without vcs", "dev", bi("(devel)"), "dev"},
		{"empty main version without vcs", "dev", bi(""), "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolve(tt.injected, tt.read, tz); got != tt.want {
				t.Errorf("resolve(%q) = %q, want %q", tt.injected, got, tt.want)
			}
		})
	}
}
