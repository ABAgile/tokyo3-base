package jetstream

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestNewAuditSink_CAOnlyDoesNotClaimMTLS(t *testing.T) {
	_, _, ca := writeAuditCertFiles(t)
	var logs bytes.Buffer
	sink, err := NewAuditSink[struct{}](AuditSinkConfig{URL: "nats://127.0.0.1:1", CAFile: ca, Subject: "audit", EnvPrefix: "TEST", Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if strings.Contains(logs.String(), "with mTLS") || !strings.Contains(logs.String(), "without mTLS") {
		t.Fatalf("incorrect TLS identity log: %s", logs.String())
	}
}
