package reloader_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/tls/reloader"
)

// After reloads fail past MaxStale, restoring the previously good bundle with
// its original mtime must recover trust. The restored file matches the loaded
// mtime, so recovery must not depend on the mtime gate seeing a change.
func TestCALoader_RestoredBundleRecoversAfterMaxStale(t *testing.T) {
	_, _, caPEM := writeCertKeyFiles(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	original := mtimeOf(t, caFile)

	loader := reloader.NewCALoader(caFile)
	loader.MaxStale = 100 * time.Millisecond
	if _, err := loader.Pool(); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	rewriteCA(t, caFile)
	if _, err := loader.Pool(); err != nil {
		t.Fatalf("within MaxStale: want last good pool kept, got %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if _, err := loader.Pool(); err == nil {
		t.Fatal("past MaxStale with a broken bundle: want error")
	}

	rewriteKeepingMtime(t, caFile, caPEM, original)
	if pool, err := loader.Pool(); err != nil {
		t.Fatalf("after restoring the valid bundle with its original mtime: pool=%p err=%v", pool, err)
	}
}
