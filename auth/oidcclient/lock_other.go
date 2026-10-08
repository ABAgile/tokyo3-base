//go:build !unix

package oidcclient

// lockTokens is a no-op where flock is unavailable; concurrent refreshes
// from separate processes are not serialised on these platforms.
func lockTokens() (func(), error) { return func() {}, nil }
