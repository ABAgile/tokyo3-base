package tls

import (
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/internal/randtest"
)

// The certificate's serial number is drawn from the reader, so a failed draw
// must return no certificate.
func TestSelfSignedCert_FailsWhenSerialCannotBeDrawn(t *testing.T) {
	var cert tls.Certificate
	var err error
	randtest.FailAfter(t, 0, func() { cert, err = SelfSignedCert() })
	if !errors.Is(err, randtest.ErrEntropy) || !strings.Contains(err.Error(), "generate serial") {
		t.Fatalf("err = %v, want the entropy error from the serial step", err)
	}
	if cert.Certificate != nil || cert.PrivateKey != nil {
		t.Errorf("SelfSignedCert returned a certificate alongside the error")
	}
}

// Under GODEBUG cryptocustomrand=1, ecdsa honors the reader. The key is drawn
// first, so a failed draw there must stop before any serial is drawn.
func TestSelfSignedCert_FailsWhenKeyCannotBeGeneratedUnderCustomReader(t *testing.T) {
	t.Setenv("GODEBUG", "cryptocustomrand=1")
	var cert tls.Certificate
	var err error
	randtest.FailAfter(t, 0, func() { cert, err = SelfSignedCert() })
	if !errors.Is(err, randtest.ErrEntropy) || !strings.Contains(err.Error(), "generate key") {
		t.Fatalf("err = %v, want the entropy error from the key step", err)
	}
	if cert.Certificate != nil || cert.PrivateKey != nil {
		t.Errorf("SelfSignedCert returned a certificate alongside the error")
	}
}

// Under the same setting, x509 signing draws from the reader after the serial.
// The reader serves everything up to and including the serial, then fails, so
// the failure must come from the signing step.
func TestSelfSignedCert_FailsWhenCertificateCannotBeSignedUnderCustomReader(t *testing.T) {
	t.Setenv("GODEBUG", "cryptocustomrand=1")
	var cert tls.Certificate
	var err error
	randtest.FailAfterSize(t, 16, func() { cert, err = SelfSignedCert() }) // 16 bytes: the serial
	if !errors.Is(err, randtest.ErrEntropy) || !strings.Contains(err.Error(), "create certificate") {
		t.Fatalf("err = %v, want the entropy error from the signing step", err)
	}
	if cert.Certificate != nil || cert.PrivateKey != nil {
		t.Errorf("SelfSignedCert returned a certificate alongside the error")
	}
}

// Without the setting, ecdsa ignores the reader. A failing reader must then
// surface at the serial step, not the key step. This runs after the tests that
// set GODEBUG, so it also catches the setting leaking past its test.
func TestSelfSignedCert_KeyGenerationIgnoresReaderByDefault(t *testing.T) {
	t.Setenv("GODEBUG", "")
	var err error
	randtest.FailAfter(t, 0, func() { _, err = SelfSignedCert() })
	if err == nil || !strings.Contains(err.Error(), "generate serial") {
		t.Fatalf("err = %v, want the serial step to fail; key generation should not draw from the reader", err)
	}
}
