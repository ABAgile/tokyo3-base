// Package envutil collects the small env-variable and process-helper
// utilities every cmd/main.go in the suite was duplicating: env-var
// lookups with fallback semantics, a fail-fast "required" check, a
// hostname-or-empty default for per-host identifiers, and a safe
// "close it if it's a closer" wrapper for resources that may or may
// not implement [io.Closer].
//
// These helpers are intentionally tiny and dependency-free — picking
// them out of cmd/ saves ~25 LOC per binary, gives the small surface
// one place to evolve (e.g., if the "required" path ever needs to
// return an error instead of os.Exit), and lets new daemons skip
// re-writing the same five functions.
package envutil

import (
	"fmt"
	"io"
	"os"
)

// Or returns the env var named by key, or fallback when the var is
// unset or empty. The common shape for "this has a default but
// operators may override it" — e.g., listen addresses, intervals.
func Or(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// First returns the first non-empty value among the named env vars
// (left-to-right), or "" when all are unset. Used for fallback
// chains where a specific override falls through to a shared
// material — e.g., {prefix}_NATS_CA → {prefix}_WORKLOAD_CA.
func First(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// MustEnv returns the value of the named env var. If the var is
// unset or empty, it writes "<key> is required" to stderr and
// calls os.Exit(2). Use for required-at-startup configuration
// where there's no useful recovery and propagating an error up
// the chain only adds noise.
//
// The shell pipeline running the daemon already shows the binary
// name, so the error message intentionally omits any per-binary
// prefix — operators see e.g. "AUTH_DATABASE_URL is required" with
// no ambiguity about which process emitted it.
func MustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "%s is required\n", key)
		os.Exit(2)
	}
	return v
}

// HostnameOrEmpty returns [os.Hostname]'s result on success and ""
// on error. Used as the default for per-host identifier env vars
// (e.g., CERT_AGENTD_INSTANCE, SSH_TUNNELD_INSTANCE) so the NATS
// subject hierarchy picks up a sensible per-host suffix without
// any operator action; the empty fallback keeps the singleton
// shape when the OS refuses to answer (sandboxed/init/etc.).
func HostnameOrEmpty() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// CloseIfCloser calls Close on v when v implements [io.Closer].
// Errors from Close are silently dropped. Use to safely close
// values that may or may not be closeable behind a polymorphic
// interface — e.g., audit.Sink can be a real JetStream sink with
// a Close, or a noop sink with none.
func CloseIfCloser(v any) {
	if c, ok := v.(io.Closer); ok {
		_ = c.Close()
	}
}
