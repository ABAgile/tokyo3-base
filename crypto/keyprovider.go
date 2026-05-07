package crypto

import "context"

// KeyProvider wraps and unwraps short-lived data keys (DEKs) under a longer-lived
// master key. Implementations might hold the master key in process memory, in a
// hardware module, or behind a remote KMS API. Callers depend only on the
// Wrap/Unwrap shape; they don't need to know where the master key lives.
type KeyProvider interface {
	Wrap(ctx context.Context, dek []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrappedDEK []byte) ([]byte, error)
}

// LocalKeyProvider implements KeyProvider with an in-memory 32-byte AES-256
// master key. Suitable for development and single-server deployments where the
// master key can be loaded from an env var or sealed file at startup.
type LocalKeyProvider struct {
	masterKey []byte
}

// NewLocalKeyProvider returns a LocalKeyProvider backed by the given 32-byte
// master key.
func NewLocalKeyProvider(masterKey []byte) *LocalKeyProvider {
	return &LocalKeyProvider{masterKey: masterKey}
}

func (p *LocalKeyProvider) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	return Seal(p.masterKey, dek)
}

func (p *LocalKeyProvider) Unwrap(_ context.Context, wrappedDEK []byte) ([]byte, error) {
	return Open(p.masterKey, wrappedDEK)
}
