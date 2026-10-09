package version

import "testing"

// Resolve is the exported entry point that reads the real build info. The
// assertions avoid the test binary's own VCS settings, which vary by checkout.
func TestResolve_InjectedValueWins(t *testing.T) {
	if got := Resolve("v9.9.9"); got != "v9.9.9" {
		t.Errorf("Resolve(v9.9.9) = %q, want the injected value", got)
	}
}

// Whatever the build, an empty injected value must still yield a version.
func TestResolve_EmptyInjectedIsNeverEmpty(t *testing.T) {
	if got := Resolve(""); got == "" {
		t.Error("Resolve(\"\") returned an empty version")
	}
}
