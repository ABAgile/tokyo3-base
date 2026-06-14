// Package reloader hot-reloads a workload's TLS material — the client
// cert+key pair and one or more CA trust pools — from disk, so an
// external rotator (cert-agentd, ssh-tunneld's host-cert renewer,
// manual replace, etc.) can swap files in place without restarting
// the daemon.
//
// The reloader produces [*tls.Config] values whose
// GetClientCertificate and VerifyConnection callbacks read live
// in-memory state — so rotated material applies on the next TLS
// handshake without rebuilding the http.Client or the tls.Config
// itself. [tls.Config.InsecureSkipVerify] is set to true on the
// returned configs so the standard verifier — which freezes
// RootCAs at config-construction time — doesn't compete with
// VerifyConnection's per-handshake pool snapshot.
//
// The mechanics are the base tls package's primitives —
// [CertLoader] for the pair, one [CALoader] per file-backed
// pool — so material whose file mtime has advanced is picked up at
// the next handshake with no polling required. What this package
// layers on top is orchestration: named multi-pool trust, the
// system-pool sentinel, fail-fast construction, swap/failure logging
// via the loaders' hooks, leaf-expiry telemetry, and the two refresh
// disciplines:
//
//   - Explicit refresh: caller invokes [Reloader.Refresh] from
//     wherever a new cert lands (typically a renewer's OnRenewed
//     callback). Set [Config.PollCert] = false. Suits cert-agentd
//     and other binaries that mint their own certs in-process —
//     Refresh bypasses the mtime gate, covering same-second writes
//     that per-handshake pickup would miss.
//
//   - mtime polling: [Reloader.RunPoll] probes the cert+key files'
//     mtimes on a fixed cadence. Set [Config.PollCert] = true.
//     Suits ssh-tunneld and other binaries whose cert is rotated by
//     an external agent; the poll bounds how long a rotation waits
//     for the next handshake and gives failures a warn cadence.
//
// CA bundles are always mtime-probed by RunPoll regardless of
// PollCert; they don't have a single explicit-refresh trigger
// like the cert+key pair does.
package reloader

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	btls "github.com/abagile/tokyo3-base/tls"
)

// DefaultPollInterval is the mtime-poll cadence for cert + CA bundle
// reloads. Cheap (one os.Stat per file) and a minute-scale upper
// bound on "I dropped in a new bundle, how long until daemons trust
// it?". 30s matches the cadence ssh-proxyd uses for revocation
// polling — one number for operators to think about.
const DefaultPollInterval = 30 * time.Second

// Config describes the on-disk material a [Reloader] manages.
//
// CertPath / KeyPath name the workload cert+key. Both required.
// Pools maps a caller-chosen pool name (e.g., "proxy", "certd",
// "ca") to a CA bundle PEM file. At least one pool required;
// callers reference these names when building tls.Configs via
// [Reloader.TLSConfig].
//
// PollCert controls cert+key mtime polling in [Reloader.RunPoll]:
// false leaves forced refresh to explicit [Reloader.Refresh]
// calls (cert-agentd's pattern); true enables cadenced mtime
// probing (ssh-tunneld's pattern). Either way an mtime-advanced
// pair is also picked up lazily at the next handshake.
//
// Log receives info lines on every successful cert / bundle swap
// and warn lines on reload failures (previous state stays
// live). nil ⇒ [slog.Default].
type Config struct {
	CertPath, KeyPath string
	Pools             map[string]string
	PollCert          bool
	Log               *slog.Logger
}

// Reloader composes the base tls loaders into named-pool
// orchestration. All public methods are safe for concurrent use;
// the pool map is fixed at construction.
type Reloader struct {
	pollCert bool
	log      *slog.Logger

	loader *CertLoader
	pools  map[string]*poolEntry
}

// poolEntry is one named trust pool: either a hot-reloading
// file-backed [CALoader] or a system-pool snapshot taken at
// construction (loader nil, system set). System pools have no file
// to probe and RunPoll skips them.
type poolEntry struct {
	path   string
	loader *CALoader
	system *x509.CertPool
}

// New constructs a Reloader and loads cert+key + every named pool
// once. Returns an error if any required file is missing or
// malformed at construction time — the reloader doesn't support
// partial initial loads (a daemon that can't trust upstream certs
// shouldn't start).
//
// An empty pool path in [Config.Pools] is a sentinel for
// "load from [x509.SystemCertPool]" — useful for development paths
// that connect to a public-CA-signed endpoint without pinning trust.
// System pools are snapshot at construction; they cannot be
// hot-reloaded and [Reloader.RunPoll] skips them.
func New(cfg Config) (*Reloader, error) {
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, errors.New("reloader: CertPath and KeyPath are required")
	}
	if len(cfg.Pools) == 0 {
		return nil, errors.New("reloader: at least one Pool is required")
	}
	for name := range cfg.Pools {
		if name == "" {
			return nil, errors.New("reloader: pool name must be non-empty")
		}
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	r := &Reloader{
		pollCert: cfg.PollCert, log: log,
		pools: make(map[string]*poolEntry, len(cfg.Pools)),
	}

	r.loader = NewCertLoader(cfg.CertPath, cfg.KeyPath)
	r.loader.OnSwap = func(cert *tls.Certificate, mtime time.Time) {
		var notAfter time.Time
		if cert.Leaf != nil {
			notAfter = cert.Leaf.NotAfter
		}
		log.Info("workload cert reloaded",
			"path", cfg.CertPath,
			"mtime", mtime,
			"not_after", notAfter)
	}
	r.loader.OnError = func(err error) {
		log.Warn("workload cert reload failed; keeping previous cert",
			"path", cfg.CertPath, "err", err)
	}
	if _, err := r.loader.GetClientCertificate(nil); err != nil {
		return nil, fmt.Errorf("load %s/%s: %w", cfg.CertPath, cfg.KeyPath, err)
	}

	for name, path := range cfg.Pools {
		if path == "" {
			sys, err := x509.SystemCertPool()
			if err != nil {
				return nil, fmt.Errorf("pool %q: load system pool: %w", name, err)
			}
			r.pools[name] = &poolEntry{system: sys}
			log.Info("CA pool: system trust store", "name", name)
			continue
		}
		loader := NewCALoader(path)
		loader.OnSwap = func(raw []byte, mtime time.Time) {
			log.Info("CA bundle reloaded",
				"name", name,
				"path", path,
				"mtime", mtime,
				"fingerprint", bundleFingerprint(raw))
		}
		loader.OnError = func(err error) {
			log.Warn("CA bundle reload failed; keeping previous pool",
				"name", name, "path", path, "err", err)
		}
		if _, err := loader.Pool(); err != nil {
			return nil, fmt.Errorf("initial pool %q: %w", name, err)
		}
		r.pools[name] = &poolEntry{path: path, loader: loader}
	}
	return r, nil
}

// Refresh re-reads the cert+key from disk regardless of mtime.
// Use from external rotators' OnRenewed callbacks where the path
// has been written but mtime may or may not have advanced past
// the cached value (some filesystems coalesce mtimes within the
// same second). For passive mtime-driven pickup, prefer RunPoll
// with [Config.PollCert] = true.
func (r *Reloader) Refresh() error { return r.loader.Reload() }

// bundleFingerprint is the first 8 bytes of sha256(pem), hex-encoded.
// Short enough for human-friendly log diffing across a fleet, long
// enough that distinct bundles don't collide in practice.
func bundleFingerprint(pem []byte) string {
	sum := sha256.Sum256(pem)
	return hex.EncodeToString(sum[:8])
}

// GetClientCertificate satisfies the [tls.Config.GetClientCertificate]
// callback signature. Returns the current workload cert, re-reading
// it when the file's mtime has advanced — so a rotation propagates
// on the dial that follows it, with Refresh / RunPoll covering the
// mtime-coalesced and between-dials cases.
func (r *Reloader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return r.loader.GetClientCertificate(nil)
}

// LeafExpiry returns the loaded cert's NotAfter. Zero value when
// no cert has been loaded (only happens in test scaffolding —
// New() returns an error if the initial load fails).
func (r *Reloader) LeafExpiry() time.Time {
	cert, err := r.loader.GetClientCertificate(nil)
	if err != nil || cert.Leaf == nil {
		return time.Time{}
	}
	return cert.Leaf.NotAfter
}

// WarnIfNearExpiry emits a Warn on the reloader's configured logger
// when the leaf cert is within threshold of expiry. Use at startup
// to alert operators that the workload identity is already in its
// renewal window (typical threshold: 24 h). No-op when the cert
// hasn't loaded yet ([Reloader.LeafExpiry] is zero).
//
// msg is the human-readable warn message. The line additionally
// carries "remaining" (duration to expiry, rounded to the nearest
// second) and "not_after" (the leaf's NotAfter) structured attrs so
// alerting rules can fire on either field without parsing the
// message text.
func (r *Reloader) WarnIfNearExpiry(threshold time.Duration, msg string) {
	exp := r.LeafExpiry()
	if exp.IsZero() {
		return
	}
	if remaining := time.Until(exp); remaining < threshold {
		r.log.Warn(msg,
			"remaining", remaining.Round(time.Second),
			"not_after", exp)
	}
}

// ExpiryAttrs returns a closure that yields
// [attrName, time-until-leaf-expiry-rounded-to-seconds] on every
// call — the shape that retry-surface error-attrs hooks (e.g.,
// revcheck.Config.RefreshErrorAttrs, hostcert.Config.SignErrorAttrs,
// renew.Config.SignErrorAttrs) want so failure logs always carry the
// remaining-validity field. Operators can grep one consistent attr
// across every retry surface to see cert exhaustion approaching.
//
// The closure returns nil when the cert hasn't loaded yet — the
// underlying logger then skips emitting the attr cleanly.
func (r *Reloader) ExpiryAttrs(attrName string) func() []any {
	return func() []any {
		exp := r.LeafExpiry()
		if exp.IsZero() {
			return nil
		}
		return []any{attrName, time.Until(exp).Round(time.Second)}
	}
}

// PoolNames returns the registered pool names, sorted-stable across
// calls is not guaranteed (Go map iteration is randomised). Exposed
// for diagnostics + tests; production callers typically know their
// pool names statically.
func (r *Reloader) PoolNames() []string {
	names := make([]string, 0, len(r.pools))
	for name := range r.pools {
		names = append(names, name)
	}
	return names
}

// VerifyConnection runs full chain + hostname verification against
// the named pool's current snapshot. Wire into
// [tls.Config.VerifyConnection]; pair with
// [tls.Config.InsecureSkipVerify] = true so the standard verifier
// doesn't compete with hot-reload semantics. Most callers should
// use [Reloader.TLSConfig], which builds the right config shape
// automatically.
func (r *Reloader) VerifyConnection(poolName string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		e, ok := r.pools[poolName]
		if !ok {
			return fmt.Errorf("reloader: pool %q not registered", poolName)
		}
		if e.system != nil {
			return btls.VerifyPeerChain(e.system, cs)
		}
		return e.loader.VerifyConnection(cs)
	}
}

// TLSConfigOption tunes the [*tls.Config] returned by
// [Reloader.TLSConfig]. Use [WithServerName] when the dial doesn't
// pull SNI from elsewhere (custom dialers to a fixed host).
type TLSConfigOption func(*tls.Config)

// WithServerName sets [tls.Config.ServerName] on the returned
// config. Use when the dial doesn't supply SNI from an
// http.Transport URL — e.g., custom dialers to a fixed host.
func WithServerName(name string) TLSConfigOption {
	return func(cfg *tls.Config) { cfg.ServerName = name }
}

// TLSConfig returns a [*tls.Config] whose callbacks read live
// reloader state. poolName must name a pool registered in
// [Config.Pools] — verification will fail loudly at handshake time
// if it doesn't.
//
// The returned config has [tls.Config.InsecureSkipVerify] = true
// because hot-reload of the root pool requires
// [tls.Config.VerifyConnection] to read pool state on every
// handshake; the standard verifier freezes RootCAs at
// config-construction. See package godoc.
func (r *Reloader) TLSConfig(poolName string, opts ...TLSConfigOption) *tls.Config {
	cfg := &tls.Config{
		GetClientCertificate: r.GetClientCertificate,
		InsecureSkipVerify:   true, //nolint:gosec // VerifyConnection below provides equivalent verification against the live pool.
		VerifyConnection:     r.VerifyConnection(poolName),
		MinVersion:           tls.VersionTLS12,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// RunPoll ticks every interval and probes files whose mtime may
// have advanced — always every file-backed CA pool, plus the
// cert+key pair when [Config.PollCert] is true. The probes are the
// loaders' own lazy paths, so swap and failure handling (previous
// state stays live, warn logged) come from the loader hooks wired
// at construction; the tick just bounds how long a rotation waits
// for the next handshake. Returns when ctx is cancelled.
func (r *Reloader) RunPoll(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if r.pollCert {
				_, _ = r.loader.GetClientCertificate(nil)
			}
			for _, e := range r.pools {
				if e.loader != nil {
					_, _ = e.loader.Pool()
				}
			}
		}
	}
}
