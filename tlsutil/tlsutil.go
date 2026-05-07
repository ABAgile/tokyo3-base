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

package tlsutil

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

// GetCertificate satisfies tls.Config.GetCertificate.
func (c *CertLoader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
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
