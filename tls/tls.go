// Package tls holds stateless TLS helpers: *tls.Config builders, PEM
// parsing, a self-signed dev fallback, and peer-chain verification.
// Everything here reads its inputs once and returns — no caching, no
// goroutines, no lifecycle.
//
// FromFiles / FromPEM build a *tls.Config from PEM material on disk or
// already in memory; both return (nil, nil) when given no inputs so
// callers can switch transparently between TLS and plaintext.
// CertPoolFromPEM / CertPoolFromFile parse a trust pool. SelfSignedCert
// generates an ephemeral cert covering localhost and *.localhost, a
// fallback when no cert files are configured. VerifyPeerChain runs
// chain + hostname verification of a peer against a root pool.
//
// For TLS material that rotates under a running process — the leaf
// reloaded per handshake, the CA pool re-read on change — use the
// hot-reloading loaders and orchestrator in [tls/reloader], which
// compose these helpers.
package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

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
	pemData, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	pool, err := CertPoolFromPEM([]byte(pemData))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return pool, nil
}

// FromFiles builds a *tls.Config from PEM file paths — the path-taking
// counterpart of [FromPEM], to which it delegates all cert-pair and CA-pool
// handling after reading each file. certFile and keyFile must both be set or
// both empty. caFile is optional; if non-empty its PEM certs populate RootCAs.
// Returns nil, nil when all arguments are empty (caller uses plain connection).
func FromFiles(certFile, keyFile, caFile string) (*tls.Config, error) {
	certPEM, err := readPEM(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readPEM(keyFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := readPEM(caFile)
	if err != nil {
		return nil, err
	}
	return FromPEM(certPEM, keyPEM, caPEM)
}

// readPEM reads path and returns its contents, or "" when path is empty —
// the not-configured sentinel [FromPEM] understands, so an unset path maps
// cleanly to an absent PEM block rather than a read error.
func readPEM(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return string(b), nil
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
		pool, err := CertPoolFromPEM([]byte(caPEM))
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}

	return cfg, nil
}

// VerifyPeerChain runs full chain + hostname verification of the
// peer chain in cs against roots: roots as the trust anchors,
// intermediates from the rest of the peer chain, DNSName from the
// connection's SNI. The building block under the hot-reloading
// verification in [tls/reloader] — both its CALoader and per-pool
// Reloader verification pair it with InsecureSkipVerify, which
// disables the standard verifier that would otherwise freeze RootCAs
// at config construction.
func VerifyPeerChain(roots *x509.CertPool, cs tls.ConnectionState) error {
	if roots == nil {
		return errors.New("no CA pool loaded")
	}
	if len(cs.PeerCertificates) == 0 {
		return errors.New("peer presented no certificates")
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		DNSName:       cs.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := cs.PeerCertificates[0].Verify(opts)
	return err
}
