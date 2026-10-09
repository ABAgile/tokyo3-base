package jetstream_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/journal/jetstream"
)

// Audit wiring must refuse to start when its TLS material cannot be loaded, so a
// misconfigured cert path cannot silently fall back to plaintext.
func TestNewAuditSink_UnloadableTLSMaterialFailsStartup(t *testing.T) {
	missing := t.TempDir()
	_, err := jetstream.NewAuditSink[testEntry](jetstream.AuditSinkConfig{
		URL:       "nats://127.0.0.1:1",
		CertFile:  filepath.Join(missing, "cert.pem"),
		KeyFile:   filepath.Join(missing, "key.pem"),
		CAFile:    filepath.Join(missing, "ca.pem"),
		Subject:   "test.audit.events",
		EnvPrefix: "TEST_NATS",
	})
	if err == nil || !strings.Contains(err.Error(), "nats audit TLS") {
		t.Fatalf("err = %v, want an audit TLS load error", err)
	}
}

func TestNewAuditSource_UnloadableTLSMaterialFailsStartup(t *testing.T) {
	missing := t.TempDir()
	_, err := jetstream.NewAuditSource(jetstream.AuditSourceConfig{
		URL:        "nats://127.0.0.1:1",
		CertFile:   filepath.Join(missing, "cert.pem"),
		KeyFile:    filepath.Join(missing, "key.pem"),
		CAFile:     filepath.Join(missing, "ca.pem"),
		StreamName: "test_audit",
		Subject:    "test.audit.events",
		EnvPrefix:  "TEST_NATS",
	})
	if err == nil || !strings.Contains(err.Error(), "nats audit source TLS") {
		t.Fatalf("err = %v, want an audit source TLS load error", err)
	}
}

// A configuration error from the underlying sink must reach the caller, not be
// swallowed by the audit wrapper.
func TestNewAuditSink_SinkConfigErrorIsReturned(t *testing.T) {
	_, err := jetstream.NewAuditSink[testEntry](jetstream.AuditSinkConfig{
		URL:       "nats://127.0.0.1:1",
		EnvPrefix: "TEST_NATS", // Subject deliberately empty
	})
	if err == nil || !strings.Contains(err.Error(), "subject required") {
		t.Fatalf("err = %v, want the sink's subject-required error", err)
	}
}
