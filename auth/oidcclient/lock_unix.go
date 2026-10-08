//go:build unix

package oidcclient

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// lockPollInterval is how often a blocked lockTokens re-checks the lock and ctx.
const lockPollInterval = 25 * time.Millisecond

// lockTokens takes an exclusive advisory lock serialising token refreshes
// across processes sharing the SSO cache, and returns its release func. It
// gives up when ctx is done.
func lockTokens(ctx context.Context) (func(), error) {
	dir, err := CacheDir()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".tokens.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(lockPollInterval):
		}
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
