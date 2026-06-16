package reloader

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
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
	certFile string
	keyFile  string

	// OnSwap, when non-nil, is called after each successful load with
	// the new cert and the cert file's mtime (zero when stat failed).
	OnSwap func(cert *tls.Certificate, mtime time.Time)
	// OnError, when non-nil, is called when a lazy (per-handshake)
	// reload attempt fails and the previously loaded cert is kept —
	// the only path where the error would otherwise be invisible.
	// Forced [CertLoader.Reload] failures return the error instead.
	OnError func(err error)

	mu      sync.RWMutex
	cert    *tls.Certificate
	modTime time.Time
}

// NewCertLoader creates a CertLoader. The cert/key are loaded lazily on first
// handshake.
func NewCertLoader(certFile, keyFile string) *CertLoader {
	return &CertLoader{certFile: certFile, keyFile: keyFile}
}

// GetCertificate satisfies tls.Config.GetCertificate (server side).
func (c *CertLoader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.current()
}

// GetClientCertificate satisfies tls.Config.GetClientCertificate
// (client side). Wire it into a client tls.Config so a long-lived
// connection (e.g. NATS) presents the freshly rotated leaf on every
// handshake — the stat-and-reload logic is shared with
// GetCertificate, so a short-TTL workload cert swapped in place by an
// external rotator is picked up on the next (re)connect without a
// process restart.
func (c *CertLoader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return c.current()
}

// current returns the loaded cert, reloading from disk when the cert
// file's mtime has advanced. Shared by GetCertificate and
// GetClientCertificate.
func (c *CertLoader) current() (*tls.Certificate, error) {
	fi, statErr := os.Stat(c.certFile)

	c.mu.RLock()
	upToDate := c.cert != nil && statErr == nil && !fi.ModTime().After(c.modTime)
	if upToDate {
		cert := c.cert
		c.mu.RUnlock()
		return cert, nil
	}
	c.mu.RUnlock()

	// Cert is stale or not yet loaded — reload. A failure with a
	// previous cert loaded falls back to it (rotation in progress:
	// cert written, key not yet) so in-flight handshakes survive;
	// OnError has already surfaced the swallowed error.
	cert, err := c.reload(false)
	if err != nil && cert != nil {
		return cert, nil
	}
	return cert, err
}

// Reload re-reads the pair from disk regardless of mtime. Use from
// rotators' post-write callbacks where mtime may not have advanced
// past the cached value (same-second writes on coarse filesystems).
// On failure the previous cert stays live and the error is returned.
func (c *CertLoader) Reload() error {
	_, err := c.reload(true)
	return err
}

// reload re-reads the cert+key. forced skips the mtime gate. Returns
// (previous cert, error) when the read fails with a previous cert
// loaded — callers decide whether to surface or swallow. Hooks fire
// outside the lock.
func (c *CertLoader) reload(forced bool) (*tls.Certificate, error) {
	fi, statErr := os.Stat(c.certFile)
	var mtime time.Time
	if statErr == nil {
		mtime = fi.ModTime()
	}

	c.mu.Lock()
	// Double-check under write lock.
	if !forced && c.cert != nil && statErr == nil && !mtime.After(c.modTime) {
		cert := c.cert
		c.mu.Unlock()
		return cert, nil
	}
	newCert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		prev := c.cert
		c.mu.Unlock()
		err = fmt.Errorf("load cert pair: %w", err)
		if prev != nil && !forced && c.OnError != nil {
			c.OnError(err)
		}
		return prev, err
	}
	c.cert = &newCert
	if statErr == nil {
		c.modTime = mtime
	}
	c.mu.Unlock()
	if c.OnSwap != nil {
		c.OnSwap(&newCert, mtime)
	}
	return &newCert, nil
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
	caFile string

	// OnSwap, when non-nil, is called after each successful load with
	// the bundle's raw PEM bytes and the file's mtime (zero when stat
	// failed).
	OnSwap func(raw []byte, mtime time.Time)
	// OnError, when non-nil, is called when a reload attempt fails
	// and the previously loaded pool is kept — the only path where
	// the error would otherwise be invisible.
	OnError func(err error)

	mu      sync.RWMutex
	pool    *x509.CertPool
	modTime time.Time
}

// NewCALoader creates a CALoader. The bundle is loaded lazily on
// first use; call [CALoader.Pool] eagerly to fail fast on a missing
// or malformed file.
func NewCALoader(caFile string) *CALoader {
	return &CALoader{caFile: caFile}
}

// Pool returns the loaded CA pool, re-reading the file when its
// mtime has advanced. Shared by VerifyConnection and eager startup
// checks. A reload failure with a previous pool loaded keeps it live
// (OnError surfaces the swallowed error); with nothing loaded the
// error is returned.
func (l *CALoader) Pool() (*x509.CertPool, error) {
	fi, statErr := os.Stat(l.caFile)
	var mtime time.Time
	if statErr == nil {
		mtime = fi.ModTime()
	}

	l.mu.RLock()
	upToDate := l.pool != nil && statErr == nil && !mtime.After(l.modTime)
	if upToDate {
		pool := l.pool
		l.mu.RUnlock()
		return pool, nil
	}
	l.mu.RUnlock()

	l.mu.Lock()
	// Double-check under write lock.
	if l.pool != nil && statErr == nil && !mtime.After(l.modTime) {
		pool := l.pool
		l.mu.Unlock()
		return pool, nil
	}

	raw, err := os.ReadFile(l.caFile)
	var pool *x509.CertPool
	if err != nil {
		err = fmt.Errorf("read %s: %w", l.caFile, err)
	} else {
		pool, err = btls.CertPoolFromPEM(raw)
		if err != nil {
			err = fmt.Errorf("%s: %w", l.caFile, err)
		}
	}
	if err != nil {
		// Keep the previous pool live across a failed reload.
		prev := l.pool
		l.mu.Unlock()
		if prev != nil {
			if l.OnError != nil {
				l.OnError(err)
			}
			return prev, nil
		}
		return nil, err
	}
	l.pool = pool
	if statErr == nil {
		l.modTime = mtime
	}
	l.mu.Unlock()
	if l.OnSwap != nil {
		l.OnSwap(raw, mtime)
	}
	return pool, nil
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
	}
	return cfg, nil
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
