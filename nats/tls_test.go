package nats

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/internal/livetest"
	btls "github.com/abagile/tokyo3-base/tls"
	"github.com/nats-io/nats.go"
)

// writeMTLSFiles writes a self-signed client certificate, its key, and the CA
// bundle to temp files, and returns their paths.
func writeMTLSFiles(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()
	cert, err := btls.SelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	caFile = filepath.Join(dir, "ca.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for path, data := range map[string][]byte{certFile: certPEM, keyFile: keyPEM, caFile: certPEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return certFile, keyFile, caFile
}

// firstByte is what the broker saw from the client: its first byte, if any.
type firstByte struct {
	b  byte
	ok bool
}

// plaintextBroker accepts one connection, sends a plaintext INFO line as a NATS
// server would, and reports the first byte the client sent back (ok is false
// if the client sent nothing).
func plaintextBroker(t *testing.T) (addr string, firstBytes <-chan firstByte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	first := make(chan firstByte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			first <- firstByte{}
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("INFO {\"server_id\":\"fake\",\"max_payload\":1048576}\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, err := bufio.NewReader(conn).ReadByte()
		first <- firstByte{b: b, ok: err == nil}
	}()
	return ln.Addr().String(), first
}

// With mTLS material configured, Dial must negotiate TLS and must refuse a
// server that only speaks plaintext. It must not connect unencrypted.
func TestDial_MTLSRefusesPlaintextServer(t *testing.T) {
	certFile, keyFile, caFile := writeMTLSFiles(t)
	addr, firstBytes := plaintextBroker(t)

	nc, err := Dial("nats://"+addr, certFile, keyFile, caFile, nats.Timeout(3*time.Second))
	if err == nil {
		nc.Close()
		t.Fatal("Dial with TLS material connected to a plaintext server")
	}
	if nc != nil {
		t.Errorf("a connection was returned alongside the error")
	}
	// The client may send nothing, or a TLS ClientHello (record type 0x16). It
	// must never send NATS protocol text in the clear, which would begin with
	// the command name, such as CONNECT.
	select {
	case got := <-firstBytes:
		if got.ok && got.b != 0x16 {
			t.Errorf("client sent plaintext protocol bytes starting %#x", got.b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("broker never reported the client's first byte")
	}
}

// The same refusal against the sandbox NATS server, which is plaintext. Runs
// only when BASE_TEST_NATS_URL is set.
func TestLiveDial_MTLSRefusesPlaintextServer(t *testing.T) {
	url := livetest.NATSURL(t)
	certFile, keyFile, caFile := writeMTLSFiles(t)

	nc, err := Dial(url, certFile, keyFile, caFile, nats.Timeout(3*time.Second))
	if err == nil {
		nc.Close()
		t.Fatal("Dial with TLS material connected to the plaintext NATS server")
	}
}
