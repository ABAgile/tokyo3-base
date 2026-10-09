package reloader

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	btls "github.com/abagile/tokyo3-base/tls"
)

// CertLoader hot-reloads a cert/key pair from disk when the cert file's mtime
// changes. Assign (*CertLoader).GetCertificate to tls.Config.GetCertificate
// for transparent rotation without server restart — the low-level primitive
// for the server-cert-rotation case, used standalone or composed by
// [Reloader] and [ClientConfig].
//
// If a reload fails (e.g. rotation in progress, key not yet written), the
// previously loaded certificate is returned so in-flight handshakes are
// unaffected.
//
// OnSwap and OnError are optional observation hooks for orchestrators
// (chiefly [Reloader]) that need to log swaps or surface swallowed
// reload failures. Set them before the loader's first use; they are
// invoked outside the loader's lock and must not call back into it.
type CertLoader struct {
	// OnSwap, when non-nil, is called after each successful load with
	// the new cert and the cert file's mtime (zero when stat failed).
	OnSwap func(cert *tls.Certificate, mtime time.Time)
	// OnError, when non-nil, is called when a lazy (per-handshake)
	// reload attempt fails and the previously loaded cert is kept —
	// the only path where the error would otherwise be invisible.
	// Forced [CertLoader.Reload] failures return the error instead.
	OnError func(err error)

	val fileValue[*tls.Certificate]
}

// NewCertLoader creates a CertLoader. The cert/key are loaded lazily on first
// handshake.
func NewCertLoader(certFile, keyFile string) *CertLoader {
	c := &CertLoader{}
	c.val = fileValue[*tls.Certificate]{
		files: []string{certFile, keyFile},
		read: func() (*tls.Certificate, []byte, error) {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, nil, fmt.Errorf("load cert pair: %w", err)
			}
			return &cert, nil, nil
		},
		swapped: func(cert *tls.Certificate, _ []byte, mtime time.Time) {
			if c.OnSwap != nil {
				c.OnSwap(cert, mtime)
			}
		},
		failed: func(err error) {
			if c.OnError != nil {
				c.OnError(err)
			}
		},
	}
	return c
}

// GetCertificate satisfies tls.Config.GetCertificate (server side).
func (c *CertLoader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.val.get(false)
}

// GetClientCertificate satisfies tls.Config.GetClientCertificate
// (client side). Wire it into a client tls.Config so a long-lived
// connection (e.g. NATS) presents the freshly rotated leaf on every
// handshake — the stat-and-reload logic is shared with
// GetCertificate, so a short-TTL workload cert swapped in place by an
// external rotator is picked up on the next (re)connect without a
// process restart.
func (c *CertLoader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return c.val.get(false)
}

// Reload re-reads the pair from disk regardless of mtime. Use from
// rotators' post-write callbacks where mtime may not have advanced
// past the cached value (same-second writes on coarse filesystems).
// On failure the previous cert stays live and the error is returned.
func (c *CertLoader) Reload() error {
	_, err := c.val.get(true)
	return err
}

// CALoader hot-reloads a CA bundle from disk when the file's mtime
// changes, mirroring [CertLoader] for the trust side: wire
// (*CALoader).VerifyConnection into tls.Config.VerifyConnection (with
// InsecureSkipVerify set, since the standard verifier freezes RootCAs
// at config construction) so a CA rotation dropped in place is
// honored on the next handshake without a process restart.
//
// If a reload fails (rotation in progress, corrupt drop-in), the
// previously loaded pool is kept so a bad write never opens a trust
// window or kills in-flight reconnects.
//
// OnSwap and OnError mirror [CertLoader]'s hooks: optional
// observation points for orchestrators that log swaps (OnSwap
// receives the raw PEM for fingerprinting) or surface swallowed
// reload failures. Set before first use; invoked outside the lock.
type CALoader struct {
	// OnSwap, when non-nil, is called after each successful load with
	// the bundle's raw PEM bytes and the file's mtime (zero when stat
	// failed).
	OnSwap func(raw []byte, mtime time.Time)
	// OnError, when non-nil, is called when a reload attempt fails
	// and the previously loaded pool is kept — the only path where
	// the error would otherwise be invisible.
	OnError func(err error)

	// MaxStale, when > 0, bounds how long the last good pool is kept after
	// reloads start failing: once failures have lasted longer than MaxStale,
	// Pool returns the failure instead. This stops a CA removed in a bundle
	// that no longer parses from staying trusted indefinitely. Zero keeps the
	// last good pool for as long as the file stays unloadable. Set before
	// first use.
	MaxStale time.Duration

	val fileValue[*x509.CertPool]
}

// NewCALoader creates a CALoader. The bundle is loaded lazily on
// first use; call [CALoader.Pool] eagerly to fail fast on a missing
// or malformed file.
func NewCALoader(caFile string) *CALoader {
	l := &CALoader{}
	l.val = fileValue[*x509.CertPool]{
		files: []string{caFile},
		read: func() (*x509.CertPool, []byte, error) {
			raw, err := os.ReadFile(caFile)
			if err != nil {
				return nil, nil, fmt.Errorf("read %s: %w", caFile, err)
			}
			pool, err := btls.CertPoolFromPEM(raw)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", caFile, err)
			}
			return pool, raw, nil
		},
		swapped: func(_ *x509.CertPool, raw []byte, mtime time.Time) {
			if l.OnSwap != nil {
				l.OnSwap(raw, mtime)
			}
		},
		failed: func(err error) {
			if l.OnError != nil {
				l.OnError(err)
			}
		},
		maxStale: func() time.Duration { return l.MaxStale },
	}
	return l
}

// Pool returns the loaded CA pool, re-reading the file when its
// mtime has advanced. Shared by VerifyConnection and eager startup
// checks. A reload failure with a previous pool loaded keeps it live
// (OnError surfaces the swallowed error) until MaxStale, if set, has
// elapsed; with nothing loaded the error is returned.
func (l *CALoader) Pool() (*x509.CertPool, error) {
	return l.val.get(false)
}

// Reload re-reads the bundle regardless of mtime. Use from rotators'
// post-write callbacks where the file was rewritten but its mtime may not
// have advanced past the cached value (same-second writes on coarse
// filesystems). On failure the previous pool stays live and the error is
// returned rather than reported through OnError.
func (l *CALoader) Reload() error {
	_, err := l.val.get(true)
	return err
}

// VerifyConnection runs full chain + hostname verification against
// the current pool snapshot via [btls.VerifyPeerChain]. Wire into
// tls.Config.VerifyConnection paired with InsecureSkipVerify.
func (l *CALoader) VerifyConnection(cs tls.ConnectionState) error {
	pool, err := l.Pool()
	if err != nil {
		return fmt.Errorf("ca bundle: %w", err)
	}
	return btls.VerifyPeerChain(pool, cs)
}

// WireClientCAs installs hot-reloading client-CA verification onto cfg
// using l as the trust source: it sets cfg.ClientAuth, loads the bundle
// once (failing fast on a missing or empty file), seeds cfg.ClientCAs
// with that pool, and installs a cfg.GetConfigForClient that re-reads l
// (mtime-gated, keep-last-good) on every handshake — so a client-CA
// rotation lands without a server restart.
//
// It's the server-side counterpart to [ClientConfig]'s CA handling, but
// uses a different mechanism for a reason: a client verifies the server's
// cert against RootCAs, which the standard verifier freezes at config
// construction (hence ClientConfig's InsecureSkipVerify + VerifyConnection
// dance). A server instead has GetConfigForClient — a per-handshake hook
// that hands the stack a fresh *tls.Config — so the client cert can be
// verified by the STANDARD verifier (correct ClientAuth EKU, the
// RequireAndVerify-vs-VerifyIfGiven policy, name constraints) against a
// freshly swapped ClientCAs pool, with no InsecureSkipVerify on the server.
//
// Set l.OnSwap/OnError before calling if you want the initial load logged.
// Call after the rest of cfg is configured: the per-handshake clone is
// taken from cfg at handshake time, so fields set later are still
// reflected (with the callback cleared on the clone to avoid recursion).
func (l *CALoader) WireClientCAs(cfg *tls.Config, auth tls.ClientAuthType) error {
	pool, err := l.Pool()
	if err != nil {
		return err
	}
	cfg.ClientAuth = auth
	cfg.ClientCAs = pool
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		// l.Pool keeps the last good pool across a failed reload, so after
		// the eager load above this only errors if the file is later
		// removed AND never successfully reloaded — never on the happy path.
		pool, err := l.Pool()
		if err != nil {
			return nil, err
		}
		c := cfg.Clone()
		c.GetConfigForClient = nil // returned config is used as-is; drop the closure ref and avoid recursion
		c.ClientCAs = pool
		return c, nil
	}
	return nil
}

// ClientConfig builds a *tls.Config for an mTLS client whose leaf
// cert+key are reloaded from disk on every handshake (via
// [CertLoader.GetClientCertificate]) and whose CA trust pool is
// re-read from caFile when its mtime advances (via
// [CALoader.VerifyConnection]). It targets long-lived clients —
// chiefly the NATS log/audit connection — whose TLS material is
// rotated in place by an external agent (cert-agentd): each reconnect
// re-handshakes and picks up the current leaf and roots, so shipping
// survives both leaf and CA rotation without a restart.
//
// This is the single-pool client shortcut; for named multi-pool
// trust, expiry telemetry, and the poll/refresh disciplines, use
// [Reloader] + [Reloader.TLSConfig].
//
// certFile and keyFile are required (this is the mTLS path; use
// [btls.FromFiles] for the optional/plaintext case). Both the pair and
// the CA bundle are loaded once up front so missing or malformed
// material fails the dial loudly rather than at the first handshake.
// caFile is optional — empty leaves RootCAs nil (system roots,
// standard verification). When caFile is set the config carries
// InsecureSkipVerify with [CALoader.VerifyConnection] providing
// equivalent chain + hostname verification against the live pool —
// the standard verifier freezes RootCAs at construction, which is
// exactly what hot-reload must avoid.
func ClientConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("client cert and key must both be provided")
	}
	loader := NewCertLoader(certFile, keyFile)
	if _, err := loader.GetClientCertificate(nil); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		GetClientCertificate: loader.GetClientCertificate,
		MinVersion:           tls.VersionTLS12,
	}
	if caFile != "" {
		ca := NewCALoader(caFile)
		if _, err := ca.Pool(); err != nil {
			return nil, err
		}
		cfg.InsecureSkipVerify = true //nolint:gosec // VerifyConnection provides equivalent verification against the live pool.
		cfg.VerifyConnection = ca.VerifyConnection
		fallbackServerName(cfg)
	}
	return cfg, nil
}

// fallbackServerName wraps cfg.VerifyConnection so a handshake that reports no
// server name (the target is an IP literal, so no SNI was sent) is verified
// against cfg.ServerName instead — typically set by the caller — rather than
// skipping hostname verification. Read at handshake time, so a ServerName set
// after the call still applies.
func fallbackServerName(cfg *tls.Config) {
	verify := cfg.VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if cs.ServerName == "" {
			cs.ServerName = cfg.ServerName
		}
		return verify(cs)
	}
}

// ClientTLS builds the outbound client TLS config a daemon presents to a TLS
// server (Postgres, a SCIM endpoint, …) from optional file paths. It is the
// "optional client cert" companion to [ClientConfig]:
//
//   - a full cert+key pair ⇒ [ClientConfig] — a hot-reloading mTLS config (leaf
//     re-read per handshake, CA pool on mtime), so a cert-agentd rotation lands
//     without a restart;
//   - no pair ⇒ [btls.FromFiles] — a one-shot config that STILL verifies the
//     server against caFile when one is set (fail-secure: an operator who
//     provides a CA gets verification regardless of a client cert), or
//     (nil, nil) when nothing is configured so the caller falls back to the
//     DSN's sslmode / plaintext.
//
// Use it wherever the client cert is optional; for the always-mTLS case call
// [ClientConfig] directly, and for an always-one-shot config (e.g. a
// short-lived migration connection that closes before any rotation matters)
// call [btls.FromFiles].
func ClientTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile != "" && keyFile != "" {
		return ClientConfig(certFile, keyFile, caFile)
	}
	return btls.FromFiles(certFile, keyFile, caFile)
}

// NewClientCALoader is a convenience that creates a [CALoader] for caFile
// and wires it onto cfg via [CALoader.WireClientCAs], returning the loader
// so the caller can inspect it. As a side effect it sets cfg.ClientAuth,
// cfg.ClientCAs, and cfg.GetConfigForClient. To log the initial load,
// create the loader yourself, set OnSwap/OnError, then call WireClientCAs
// directly.
func NewClientCALoader(cfg *tls.Config, caFile string, auth tls.ClientAuthType) (*CALoader, error) {
	l := NewCALoader(caFile)
	if err := l.WireClientCAs(cfg, auth); err != nil {
		return nil, err
	}
	return l, nil
}
