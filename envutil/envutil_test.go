package envutil_test

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/envutil"
)

func TestOr_ReturnsFallbackWhenUnset(t *testing.T) {
	// t.Setenv guarantees cleanup; the var is forcibly unset for the
	// test even if it leaked in from the environment.
	t.Setenv("ENVUTIL_TEST_OR", "")
	_ = os.Unsetenv("ENVUTIL_TEST_OR")
	if got := envutil.Or("ENVUTIL_TEST_OR", "fb"); got != "fb" {
		t.Errorf("Or unset = %q, want fb", got)
	}
}

func TestOr_ReturnsValueWhenSet(t *testing.T) {
	t.Setenv("ENVUTIL_TEST_OR", "set")
	if got := envutil.Or("ENVUTIL_TEST_OR", "fb"); got != "set" {
		t.Errorf("Or set = %q, want set", got)
	}
}

func TestOr_EmptyStringTreatedAsUnset(t *testing.T) {
	// Setting a var to "" is semantically the same as not setting it
	// for this helper — callers expect fallback when there's no
	// meaningful value to read.
	t.Setenv("ENVUTIL_TEST_OR", "")
	if got := envutil.Or("ENVUTIL_TEST_OR", "fb"); got != "fb" {
		t.Errorf("Or with explicit empty = %q, want fb", got)
	}
}

func TestFirst_PicksFirstNonEmpty(t *testing.T) {
	_ = os.Unsetenv("ENVUTIL_TEST_A")
	t.Setenv("ENVUTIL_TEST_B", "from-b")
	t.Setenv("ENVUTIL_TEST_C", "from-c")
	if got := envutil.First("ENVUTIL_TEST_A", "ENVUTIL_TEST_B", "ENVUTIL_TEST_C"); got != "from-b" {
		t.Errorf("First = %q, want from-b", got)
	}
}

func TestFirst_AllUnsetReturnsEmpty(t *testing.T) {
	_ = os.Unsetenv("ENVUTIL_TEST_X")
	_ = os.Unsetenv("ENVUTIL_TEST_Y")
	if got := envutil.First("ENVUTIL_TEST_X", "ENVUTIL_TEST_Y"); got != "" {
		t.Errorf("First all-unset = %q, want empty", got)
	}
}

func TestFirst_NoKeysReturnsEmpty(t *testing.T) {
	// Defensive: zero-arg form must not panic.
	if got := envutil.First(); got != "" {
		t.Errorf("First() = %q, want empty", got)
	}
}

// TestMustEnv_ReturnsValueWhenSet exercises the happy path. The
// os.Exit branch is tested in TestMustEnv_ExitsWhenUnset using the
// reexec-with-env-flag trick so we don't terminate the test process.
func TestMustEnv_ReturnsValueWhenSet(t *testing.T) {
	t.Setenv("ENVUTIL_TEST_MUST", "ok")
	if got := envutil.MustEnv("ENVUTIL_TEST_MUST"); got != "ok" {
		t.Errorf("MustEnv = %q, want ok", got)
	}
}

// TestMustEnv_ExitsWhenUnset reinvokes this test binary with a flag
// env that makes the inner branch call MustEnv on an unset var.
// The inner process should exit(2); the outer asserts on the exit
// code and the stderr message.
func TestMustEnv_ExitsWhenUnset(t *testing.T) {
	if os.Getenv("ENVUTIL_TEST_INNER") == "1" {
		// We're the reexec child — actually call MustEnv. It should
		// print to stderr and exit(2), so the rest of this function
		// is unreachable in the child.
		_ = os.Unsetenv("ENVUTIL_TEST_MISSING")
		envutil.MustEnv("ENVUTIL_TEST_MISSING")
		t.Fatal("MustEnv returned instead of exiting")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMustEnv_ExitsWhenUnset")
	cmd.Env = append(os.Environ(), "ENVUTIL_TEST_INNER=1")
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("inner did not exit non-zero; err=%v out=%s", err, out)
	}
	if got := exitErr.ExitCode(); got != 2 {
		t.Errorf("inner exit code = %d, want 2", got)
	}
	if !strings.Contains(string(out), "ENVUTIL_TEST_MISSING is required") {
		t.Errorf("stderr missing required-message: %s", out)
	}
}

func TestHostnameOrEmpty_ReturnsNonEmpty(t *testing.T) {
	// On every supported platform os.Hostname succeeds. The "or
	// empty" branch is exercised only when the OS itself refuses,
	// which can't be triggered from a test. Verifying the success
	// path is enough to confirm the function isn't accidentally
	// returning "" all the time.
	if got := envutil.HostnameOrEmpty(); got == "" {
		t.Error("HostnameOrEmpty returned empty; expected a real hostname on this platform")
	}
}

func TestCloseIfCloser_CallsCloseOnCloser(t *testing.T) {
	c := &recordingCloser{}
	envutil.CloseIfCloser(c)
	if !c.closed {
		t.Error("CloseIfCloser did not call Close on a Closer-implementing value")
	}
}

func TestCloseIfCloser_NoOpOnNonCloser(t *testing.T) {
	// Must not panic on values that don't implement io.Closer.
	envutil.CloseIfCloser("not a closer")
	envutil.CloseIfCloser(42)
	envutil.CloseIfCloser(struct{}{})
}

func TestCloseIfCloser_NilSafe(t *testing.T) {
	// Untyped nil is the obvious edge case; CloseIfCloser must not
	// panic dereferencing it.
	envutil.CloseIfCloser(nil)
}

type recordingCloser struct{ closed bool }

func (r *recordingCloser) Close() error {
	r.closed = true
	return nil
}
