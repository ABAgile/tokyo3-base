package crypto

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// makeTestKey returns a deterministic 32-byte key for tests.
func makeTestKey(seed byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i) + seed
	}
	return k
}

// TestKeyProviderCache_NilWrappedKey: with no wrapped key the master provider
// is returned directly so unmigrated callers stay on the master path.
func TestKeyProviderCache_NilWrappedKey(t *testing.T) {
	master := NewLocalKeyProvider(makeTestKey(1))
	cache := NewKeyProviderCache(master, time.Minute)

	kp, err := cache.ForKey(context.Background(), "id-1", nil)
	if err != nil {
		t.Fatalf("ForKey(nil): %v", err)
	}
	if kp != KeyProvider(master) {
		t.Error("expected master KeyProvider when wrappedKey is nil")
	}
}

// TestKeyProviderCache_CacheHit: second call for the same id returns the same
// provider pointer (proves the slow path didn't fire twice).
func TestKeyProviderCache_CacheHit(t *testing.T) {
	master := NewLocalKeyProvider(makeTestKey(1))
	cache := NewKeyProviderCache(master, time.Minute)
	ctx := context.Background()

	wrappedKey, err := master.Wrap(ctx, makeTestKey(5))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	kp1, err := cache.ForKey(ctx, "id-x", wrappedKey)
	if err != nil {
		t.Fatalf("first ForKey: %v", err)
	}
	kp2, err := cache.ForKey(ctx, "id-x", wrappedKey)
	if err != nil {
		t.Fatalf("second ForKey: %v", err)
	}
	if kp1 != kp2 {
		t.Error("second call should return cached provider (same pointer)")
	}
}

// TestKeyProviderCache_Invalidate: after Invalidate the next ForKey call
// re-unwraps and returns a fresh provider.
func TestKeyProviderCache_Invalidate(t *testing.T) {
	master := NewLocalKeyProvider(makeTestKey(1))
	cache := NewKeyProviderCache(master, time.Minute)
	ctx := context.Background()

	wrappedKey, _ := master.Wrap(ctx, makeTestKey(7))

	kp1, _ := cache.ForKey(ctx, "id-inv", wrappedKey)
	cache.Invalidate("id-inv")
	kp2, _ := cache.ForKey(ctx, "id-inv", wrappedKey)

	if kp1 == kp2 {
		t.Error("after Invalidate, ForKey should return a fresh provider")
	}
}

// TestKeyProviderCache_ExpiredTTL: a non-positive TTL forces a cache miss
// every call.
func TestKeyProviderCache_ExpiredTTL(t *testing.T) {
	master := NewLocalKeyProvider(makeTestKey(1))
	cache := NewKeyProviderCache(master, -1*time.Second)
	ctx := context.Background()

	wrappedKey, _ := master.Wrap(ctx, makeTestKey(3))

	kp1, err := cache.ForKey(ctx, "id-exp", wrappedKey)
	if err != nil {
		t.Fatalf("first ForKey: %v", err)
	}
	kp2, err := cache.ForKey(ctx, "id-exp", wrappedKey)
	if err != nil {
		t.Fatalf("second ForKey: %v", err)
	}
	if kp1 == kp2 {
		t.Error("expired TTL should bypass cache; expected new provider each call")
	}
}

// errKP always fails Unwrap. Used to assert the cache propagates errors.
type errKP struct{}

func (errKP) Wrap(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("wrap error")
}
func (errKP) Unwrap(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("unwrap error")
}

// TestKeyProviderCache_UnwrapError: master.Unwrap failures bubble up.
func TestKeyProviderCache_UnwrapError(t *testing.T) {
	cache := NewKeyProviderCache(errKP{}, time.Minute)
	_, err := cache.ForKey(context.Background(), "id-err", []byte("bogus"))
	if err == nil {
		t.Fatal("expected error from unwrap failure, got nil")
	}
}

// countingKP records Unwrap calls and sleeps briefly so concurrent callers
// overlap in the slow path. The exact key bytes don't matter for the dedupe
// assertion — only the call count.
type countingKP struct {
	calls atomic.Int64
	delay time.Duration
}

func (p *countingKP) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	return append([]byte(nil), dek...), nil
}
func (p *countingKP) Unwrap(_ context.Context, _ []byte) ([]byte, error) {
	p.calls.Add(1)
	time.Sleep(p.delay)
	return make([]byte, 32), nil
}

// TestKeyProviderCache_SingleflightDedupe: concurrent cold misses for the
// same keyID collapse into a single master.Unwrap call. Without singleflight
// the count would be `concurrency`; with it, exactly 1.
func TestKeyProviderCache_SingleflightDedupe(t *testing.T) {
	master := &countingKP{delay: 50 * time.Millisecond}
	cache := NewKeyProviderCache(master, time.Minute)

	const concurrency = 10
	wrappedKey := []byte("any-wrappedkey-bytes")
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for range concurrency {
		go func() {
			defer wg.Done()
			<-start // release all goroutines simultaneously
			if _, err := cache.ForKey(context.Background(), "id-dedupe", wrappedKey); err != nil {
				t.Errorf("ForKey: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := master.calls.Load(); got != 1 {
		t.Errorf("expected exactly 1 Unwrap call from %d concurrent misses, got %d", concurrency, got)
	}
}
