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
// Two reload disciplines, picked per use case:
//
//   - Explicit refresh: caller invokes [Reloader.Refresh] from
//     wherever a new cert lands (typically a renewer's OnRenewed
//     callback). Set [Config.PollCert] = false. Suits cert-agentd
//     and other binaries that mint their own certs in-process.
//
//   - mtime polling: [Reloader.RunPoll] watches the cert+key files'
//     mtimes and re-reads when they advance. Set [Config.PollCert]
//     = true. Suits ssh-tunneld and other binaries whose cert is
//     rotated by an external agent.
//
// CA bundles are always mtime-polled by RunPoll regardless of
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
	"os"
	"sync"
	"time"
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
// false leaves the cert refresh to explicit [Reloader.Refresh]
// calls (cert-agentd's pattern); true enables passive mtime
// pickup (ssh-tunneld's pattern).
//
// Log receives info lines on every successful cert / bundle swap
// and warn lines on RunPoll read failures (previous state stays
// live). nil ⇒ [slog.Default].
type Config struct {
	CertPath, KeyPath string
	Pools             map[string]string
	PollCert          bool
	Log               *slog.Logger
}

// Reloader owns the in-memory cert + multi-pool state. All public
// methods are safe for concurrent use.
type Reloader struct {
	certPath, keyPath string
	pollCert          bool
	log               *slog.Logger

	mu        sync.RWMutex
	cert      *tls.Certificate
	notAfter  time.Time
	certMtime time.Time
	pools     map[string]*caBundle
}

// caBundle holds one CA pool's in-memory state. Path is stable from
// construction; pool + mtime swap atomically on mtime-advance.
// isSystem marks the pool as loaded from [x509.SystemCertPool] at
// construction — those pools have no file to poll and refreshPool
// short-circuits to a no-op.
type caBundle struct {
	path     string
	pool     *x509.CertPool
	mtime    time.Time
	isSystem bool
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
// hot-reloaded and [RunPoll] skips them.
func New(cfg Config) (*Reloader, error) {
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, errors.New("reloader: CertPath and KeyPath are required")
	}
	if len(cfg.Pools) == 0 {
		return nil, errors.New("reloader: at least one Pool is required")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	pools := make(map[string]*caBundle, len(cfg.Pools))
	for name, path := range cfg.Pools {
		if name == "" {
			return nil, errors.New("reloader: pool name must be non-empty")
		}
		pools[name] = &caBundle{path: path}
	}
	r := &Reloader{
		certPath: cfg.CertPath, keyPath: cfg.KeyPath,
		pollCert: cfg.PollCert, log: log, pools: pools,
	}
	if err := r.refreshCert(true); err != nil {
		return nil, err
	}
	for name, b := range r.pools {
		if b.path == "" {
			sys, err := x509.SystemCertPool()
			if err != nil {
				return nil, fmt.Errorf("pool %q: load system pool: %w", name, err)
			}
			r.mu.Lock()
			b.pool = sys
			b.isSystem = true
			r.mu.Unlock()
			r.log.Info("CA pool: system trust store", "name", name)
			continue
		}
		if err := r.refreshPool(name, b); err != nil {
			return nil, fmt.Errorf("initial pool %q: %w", name, err)
		}
	}
	return r, nil
}

// Refresh re-reads the cert+key from disk regardless of mtime.
// Use from external rotators' OnRenewed callbacks where the path
// has been written but mtime may or may not have advanced past
// the cached value (some filesystems coalesce mtimes within the
// same second). For passive mtime-driven pickup, prefer RunPoll
// with [Config.PollCert] = true.
func (r *Reloader) Refresh() error { return r.refreshCert(true) }

// refreshCert re-reads the cert+key pair. When forced, ignores
// mtime; otherwise no-ops on unchanged mtime + already-loaded.
// Logs at info on every actual swap so operators see rotations
// propagate.
func (r *Reloader) refreshCert(forced bool) error {
	if !forced {
		stat, err := os.Stat(r.certPath)
		if err != nil {
			return fmt.Errorf("stat %s: %w", r.certPath, err)
		}
		r.mu.RLock()
		prev := r.certMtime
		loaded := r.cert != nil
		r.mu.RUnlock()
		if !stat.ModTime().After(prev) && loaded {
			return nil
		}
	}
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("load %s/%s: %w", r.certPath, r.keyPath, err)
	}
	var notAfter time.Time
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("parse leaf %s: %w", r.certPath, err)
		}
		cert.Leaf = leaf
		notAfter = leaf.NotAfter
	}
	stat, statErr := os.Stat(r.certPath)
	var mtime time.Time
	if statErr == nil {
		mtime = stat.ModTime()
	}
	r.mu.Lock()
	r.cert = &cert
	r.notAfter = notAfter
	r.certMtime = mtime
	r.mu.Unlock()
	r.log.Info("workload cert reloaded",
		"path", r.certPath,
		"mtime", mtime,
		"not_after", notAfter)
	return nil
}

// refreshPool re-reads a CA pool when its file's mtime has advanced
// past the cached value (or on first load). Pool swap is atomic.
// Logs at info on every actual swap. No-op for system pools — they
// have no file to poll and were snapshot at construction.
func (r *Reloader) refreshPool(name string, b *caBundle) error {
	if b.isSystem {
		return nil
	}
	stat, err := os.Stat(b.path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", b.path, err)
	}
	r.mu.RLock()
	prev := b.mtime
	loaded := b.pool != nil
	r.mu.RUnlock()
	if !stat.ModTime().After(prev) && loaded {
		return nil
	}
	raw, err := os.ReadFile(b.path)
	if err != nil {
		return fmt.Errorf("read %s: %w", b.path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return fmt.Errorf("%s contains no PEM certs", b.path)
	}
	r.mu.Lock()
	b.pool = pool
	b.mtime = stat.ModTime()
	r.mu.Unlock()
	r.log.Info("CA bundle reloaded",
		"name", name,
		"path", b.path,
		"mtime", stat.ModTime(),
		"fingerprint", bundleFingerprint(raw))
	return nil
}

// bundleFingerprint is the first 8 bytes of sha256(pem), hex-encoded.
// Short enough for human-friendly log diffing across a fleet, long
// enough that distinct bundles don't collide in practice.
func bundleFingerprint(pem []byte) string {
	sum := sha256.Sum256(pem)
	return hex.EncodeToString(sum[:8])
}

// GetClientCertificate satisfies the [tls.Config.GetClientCertificate]
// callback signature. Returns the current workload cert; the
// handshake stack invokes this per dial, so a Refresh (or mtime
// pickup) between dials propagates automatically.
func (r *Reloader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cert == nil {
		return nil, errors.New("reloader: no cert loaded yet")
	}
	return r.cert, nil
}

// LeafExpiry returns the loaded cert's NotAfter. Zero value when
// no cert has been loaded (only happens in test scaffolding —
// New() returns an error if the initial load fails).
func (r *Reloader) LeafExpiry() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.notAfter
}

// WarnIfNearExpiry emits a Warn on the reloader's configured logger
// when the leaf cert is within threshold of expiry. Use at startup
// to alert operators that the workload identity is already in its
// renewal window (typical threshold: 24 h). No-op when the cert
// hasn't loaded yet ([LeafExpiry] is zero).
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
	r.mu.RLock()
	defer r.mu.RUnlock()
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
		r.mu.RLock()
		b, ok := r.pools[poolName]
		var pool *x509.CertPool
		if ok {
			pool = b.pool
		}
		r.mu.RUnlock()
		if !ok {
			return fmt.Errorf("reloader: pool %q not registered", poolName)
		}
		if pool == nil {
			return errors.New("reloader: no CA bundle loaded")
		}
		if len(cs.PeerCertificates) == 0 {
			return errors.New("reloader: peer presented no certificates")
		}
		opts := x509.VerifyOptions{
			Roots:         pool,
			DNSName:       cs.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
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

// RunPoll ticks every interval and re-reads files whose mtime has
// advanced. Always polls every CA pool. When [Config.PollCert] is
// true, also polls the cert+key pair. Read failures keep the
// previous in-memory state live and emit a warn log so a corrupt
// drop-in never opens a trust window. Returns when ctx is
// cancelled.
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
				if err := r.refreshCert(false); err != nil {
					r.log.Warn("workload cert reload failed; keeping previous cert",
						"path", r.certPath, "err", err)
				}
			}
			// Snapshot pool names so we don't hold the lock during reload.
			r.mu.RLock()
			refreshables := make([]struct {
				name string
				b    *caBundle
			}, 0, len(r.pools))
			for name, b := range r.pools {
				refreshables = append(refreshables, struct {
					name string
					b    *caBundle
				}{name, b})
			}
			r.mu.RUnlock()
			for _, e := range refreshables {
				if err := r.refreshPool(e.name, e.b); err != nil {
					r.log.Warn("CA bundle reload failed; keeping previous pool",
						"name", e.name, "path", e.b.path, "err", err)
				}
			}
		}
	}
}
