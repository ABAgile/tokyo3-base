package reloader_test

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	btls "github.com/abagile/tokyo3-base/tls"
	"github.com/abagile/tokyo3-base/tls/reloader"
)

// A hostname dial carries its name in SNI, so the hot config verifies it with
// no option. An IP-literal dial sends no SNI, and http.Transport sets
// ServerName only on its clone of the config, which the verifier cannot see.
// It must fail closed unless the caller passes WithServerName.
func TestTLSConfig_ServerNameForHostAndIPDials(t *testing.T) {
	cert, err := btls.SelfSignedCert() // SANs: localhost, *.localhost, 127.0.0.1, ::1
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	dir := t.TempDir()
	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client-key.pem")
	writePEMCertKey(t, clientCertPath, clientKeyPath, "client", 1)
	caPath := filepath.Join(dir, "server-ca.pem")
	if err := os.WriteFile(caPath, pemEncodeCert(cert.Certificate[0]), 0o644); err != nil {
		t.Fatalf("write server CA: %v", err)
	}
	r, err := reloader.New(reloader.Config{
		CertPath: clientCertPath, KeyPath: clientKeyPath,
		Pools: map[string]string{"server": caPath},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	get := func(url string, cfg *tls.Config) error {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 2 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
		return nil
	}
	ipURL := srv.URL
	hostURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	if err := get(hostURL, r.TLSConfig("server")); err != nil {
		t.Errorf("hostname dial without WithServerName: %v", err)
	}
	if err := get(ipURL, r.TLSConfig("server")); err == nil {
		t.Error("IP-literal dial without WithServerName verified; want fail-closed")
	}
	if err := get(ipURL, r.TLSConfig("server", reloader.WithServerName("127.0.0.1"))); err != nil {
		t.Errorf("IP-literal dial with WithServerName: %v", err)
	}
}
