package tls

import (
	"os"
	"path/filepath"
	"testing"
)

// An empty file at a configured path must fail, not read as "unset": an empty
// CA beside a valid pair would otherwise fall back to system trust, and an
// empty cert/key pair would fall back to plaintext.
func TestFromFiles_RejectsEmptyConfiguredFiles(t *testing.T) {
	certFile, keyFile, _ := writeCertKeyFiles(t)
	emptyCA := filepath.Join(t.TempDir(), "empty-ca.pem")
	if err := os.WriteFile(emptyCA, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	emptyCert := filepath.Join(t.TempDir(), "empty-cert.pem")
	emptyKey := filepath.Join(t.TempDir(), "empty-key.pem")
	for _, p := range []string{emptyCert, emptyKey} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name          string
		cert, key, ca string
	}{
		{"empty CA with valid pair", certFile, keyFile, emptyCA},
		{"empty CA alone", "", "", emptyCA},
		{"empty cert and key", emptyCert, emptyKey, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := FromFiles(tc.cert, tc.key, tc.ca)
			if err == nil {
				t.Fatalf("FromFiles accepted an empty configured file: cfg=%+v", cfg)
			}
		})
	}
}
