// TLS helpers: hot-reload from disk, self-signed dev fallback, PEM parsing,
// and *tls.Config builders for client connections.
//
// CertLoader stat-checks the cert file on every handshake and reloads when the
// mtime changes; assign GetCertificate to tls.Config.GetCertificate so a
// rotation tool (cert-manager, SPIFFE/SPIRE-in-disk-mode, ACME, manual) can
// replace cert/key files without a server restart.
//
// SelfSignedCert generates an ephemeral cert covering localhost and
// *.localhost — useful as a fallback when no cert files are configured.
//
// FromFiles / FromPEM build a *tls.Config from PEM
// material on disk or already in memory; both return (nil, nil) when given no
// inputs so callers can switch transparently between TLS and plaintext.

package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// CertLoader hot-reloads a cert/key pair from disk when the cert file's mtime
// changes. Assign (*CertLoader).GetCertificate to tls.Config.GetCertificate
// for transparent rotation without server restart.
//
// If a reload fails (e.g. rotation in progress, key not yet written), the
// previously loaded certificate is returned so in-flight handshakes are
// unaffected.
type CertLoader struct {
	certFile string
	keyFile  string
	mu       sync.RWMutex
	cert     *tls.Certificate
	modTime  time.Time
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

	// Cert is stale or not yet loaded — acquire write lock and reload.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check under write lock.
	if c.cert != nil && statErr == nil && !fi.ModTime().After(c.modTime) {
		return c.cert, nil
	}

	newCert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		// Rotation in progress (cert written, key not yet) — keep serving old cert.
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, fmt.Errorf("load cert pair: %w", err)
	}
	c.cert = &newCert
	if statErr == nil {
		c.modTime = fi.ModTime()
	}
	return c.cert, nil
}

// SelfSignedCert generates an ephemeral ECDSA P-256 self-signed certificate
// valid for one year. SANs cover localhost, *.localhost (single-label
// subdomains like api.localhost), and 127.0.0.1 / ::1. Used as a TLS fallback
// when no cert files are configured.
func SelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "self-signed"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "*.localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}

	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
}

// CertPoolFromPEM parses one or more PEM-encoded certificates and returns a
// CertPool.
func CertPoolFromPEM(pemData []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("no valid certificates found in PEM data")
	}
	return pool, nil
}

// CertPoolFromFile reads a PEM bundle from path and returns it as a
// new *x509.CertPool. Returns an error when the file is missing,
// unreadable, or contains zero PEM-encoded certificates — the
// zero-certs case is the load-bearing safety check, catching typo'd
// paths that would otherwise silently disable trust.
func CertPoolFromFile(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	pool, err := CertPoolFromPEM(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return pool, nil
}

// FromFiles builds a *tls.Config from PEM file paths.
// certFile and keyFile must both be set or both empty.
// caFile is optional; if non-empty its PEM certs populate RootCAs.
// Returns nil, nil when all arguments are empty (caller uses plain connection).
func FromFiles(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" && caFile == "" {
		return nil, nil
	}
	cfg := &tls.Config{}

	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("client cert and key must both be provided")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert pair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		pool, err := CertPoolFromPEM(data)
		if err != nil {
			return nil, fmt.Errorf("ca file %q: %w", caFile, err)
		}
		cfg.RootCAs = pool
	}

	return cfg, nil
}

// ReloadingClientConfig builds a *tls.Config for an mTLS client whose
// leaf cert+key are reloaded from disk on every handshake (via
// [CertLoader.GetClientCertificate]), while the CA trust pool is read
// once from caFile at construction. It targets long-lived clients —
// chiefly the NATS log/audit connection — whose short-TTL workload
// cert is rotated in place by an external agent (cert-agentd): each
// reconnect re-handshakes and picks up the current leaf, so shipping
// survives rotation without a restart.
//
// certFile and keyFile are required (this is the mTLS path; use
// [FromFiles] for the optional/plaintext case). The pair is loaded
// once up front so a missing or malformed cert fails the dial loudly
// rather than at the first handshake. caFile is optional — empty
// leaves RootCAs nil (system roots). The CA is deliberately not
// hot-reloaded: roots are long-lived, only the leaf churns, and a
// static pool keeps standard server verification (no
// InsecureSkipVerify) intact.
func ReloadingClientConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
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
		pool, err := CertPoolFromFile(caFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// FromPEM builds a *tls.Config from PEM content strings already in memory.
// certPEM and keyPEM must both be set or both empty.
// caPEM is optional. Returns nil, nil when all arguments are empty.
func FromPEM(certPEM, keyPEM, caPEM string) (*tls.Config, error) {
	if certPEM == "" && keyPEM == "" && caPEM == "" {
		return nil, nil
	}
	cfg := &tls.Config{}

	if certPEM != "" || keyPEM != "" {
		if certPEM == "" || keyPEM == "" {
			return nil, fmt.Errorf("client cert and key must both be provided")
		}
		cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("load client cert pair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if caPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, fmt.Errorf("no valid certificates in ca PEM")
		}
		cfg.RootCAs = pool
	}

	return cfg, nil
}
