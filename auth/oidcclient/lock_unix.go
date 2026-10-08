//go:build unix

package oidcclient

import (
	"os"
	"path/filepath"
	"syscall"
)

// lockTokens takes an exclusive advisory lock serialising token refreshes
// across processes sharing the SSO cache, and returns its release func.
func lockTokens() (func(), error) {
	dir, err := CacheDir()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".tokens.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
