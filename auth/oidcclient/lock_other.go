//go:build !unix

package oidcclient

import "context"

// lockTokens is a no-op where flock is unavailable; concurrent refreshes
// from separate processes are not serialised on these platforms.
func lockTokens(context.Context) (func(), error) { return func() {}, nil }
