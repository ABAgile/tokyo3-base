package reloader_test

import (
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/internal/randtest"
	"github.com/abagile/tokyo3-base/tls/reloader"
)

// With no certificate files configured, the server falls back to a self-signed
// certificate. If that cannot be generated, the server must not start.
func TestServerTLS_SelfSignedFallbackFailsWithoutConfig(t *testing.T) {
	var cfg *tls.Config
	var err error
	randtest.FailAfter(t, 0, func() {
		cfg, err = reloader.ServerTLS(reloader.ServerTLSConfig{Log: discard()})
	})
	if !errors.Is(err, randtest.ErrEntropy) || !strings.Contains(err.Error(), "generate self-signed cert") {
		t.Fatalf("err = %v, want the entropy error", err)
	}
	if cfg != nil {
		t.Error("ServerTLS returned a config alongside the error")
	}
}
