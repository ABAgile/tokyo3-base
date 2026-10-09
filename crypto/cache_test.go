package crypto

import (
	"bytes"
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

// blockingMaster blocks its first Unwrap until release is closed, returning
// the wrapped bytes as the plaintext key so tests can tell which input won.
type blockingMaster struct {
	calls            atomic.Int32
	entered, release chan struct{}
}

func (m *blockingMaster) Wrap(_ context.Context, b []byte) ([]byte, error) { return b, nil }
func (m *blockingMaster) Unwrap(_ context.Context, b []byte) ([]byte, error) {
	if m.calls.Add(1) == 1 {
		close(m.entered)
		<-m.release
	}
	return b, nil
}

// TestKeyProviderCache_StaleUnwrapDoesNotServeNewMaterial: an unwrap of the old
// wrapped key that is still running when the key is rotated and invalidated
// must not be served to callers holding the new wrapped key.
func TestKeyProviderCache_StaleUnwrapDoesNotServeNewMaterial(t *testing.T) {
	master := &blockingMaster{entered: make(chan struct{}), release: make(chan struct{})}
	cache := NewKeyProviderCache(master, time.Hour)
	ctx := context.Background()
	oldKey, newKey := makeTestKey(1), makeTestKey(2)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = cache.ForKey(ctx, "id", oldKey)
	}()
	<-master.entered
	cache.Invalidate("id") // rotation committed while the old unwrap is running

	kp, err := cache.ForKey(ctx, "id", newKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kp.(*LocalKeyProvider).masterKey, newKey) {
		t.Fatal("new material was served the old key")
	}
	close(master.release)
	<-done // stale unwrap finishes and stores its result

	kp, err = cache.ForKey(ctx, "id", newKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kp.(*LocalKeyProvider).masterKey, newKey) {
		t.Fatal("stale unwrap repopulated the cache with the old key")
	}
}

// TestKeyProviderCache_ChangedMaterialMisses: different wrapped bytes for the
// same id are never answered from the cache.
func TestKeyProviderCache_ChangedMaterialMisses(t *testing.T) {
	master := &blockingMaster{entered: make(chan struct{}), release: make(chan struct{})}
	close(master.release)
	cache := NewKeyProviderCache(master, time.Hour)
	ctx := context.Background()

	a, _ := cache.ForKey(ctx, "id", makeTestKey(1))
	b, err := cache.ForKey(ctx, "id", makeTestKey(2))
	if err != nil {
		t.Fatal(err)
	}
	if a == b || !bytes.Equal(b.(*LocalKeyProvider).masterKey, makeTestKey(2)) {
		t.Fatal("changed wrapped material was served from cache")
	}
}

// TestKeyProviderCache_ExpiredEntriesAreSwept: expired entries for other ids
// are dropped when a new entry is stored, and ttl <= 0 retains nothing.
func TestKeyProviderCache_ExpiredEntriesAreSwept(t *testing.T) {
	master := NewLocalKeyProvider(makeTestKey(1))
	cache := NewKeyProviderCache(master, 20*time.Millisecond)
	ctx := context.Background()
	wrapped, _ := master.Wrap(ctx, makeTestKey(5))

	if _, err := cache.ForKey(ctx, "a", wrapped); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	if _, err := cache.ForKey(ctx, "b", wrapped); err != nil {
		t.Fatal(err)
	}
	cache.mu.RLock()
	_, stale := cache.entries["a"]
	n := len(cache.entries)
	cache.mu.RUnlock()
	if stale || n != 1 {
		t.Fatalf("expired entry retained: stale=%v entries=%d", stale, n)
	}

	for _, ttl := range []time.Duration{0, -time.Second} {
		c := NewKeyProviderCache(master, ttl)
		if _, err := c.ForKey(ctx, "id", wrapped); err != nil {
			t.Fatal(err)
		}
		if len(c.entries) != 0 {
			t.Fatalf("ttl %v retained an entry", ttl)
		}
	}
}

// ctxAwareKP's Unwrap fails with the context's error if the context it was
// given is cancelled while it works.
type ctxAwareKP struct{ started chan struct{} }

func (ctxAwareKP) Wrap(_ context.Context, dek []byte) ([]byte, error) { return dek, nil }
func (p ctxAwareKP) Unwrap(ctx context.Context, _ []byte) ([]byte, error) {
	close(p.started)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(100 * time.Millisecond):
		return make([]byte, 32), nil
	}
}

// TestKeyProviderCache_LeaderCancelDoesNotFailWaiters: the caller that happens
// to start the shared unwrap cancelling must neither fail the unwrap for the
// other waiters nor keep waiting itself.
func TestKeyProviderCache_LeaderCancelDoesNotFailWaiters(t *testing.T) {
	master := ctxAwareKP{started: make(chan struct{})}
	cache := NewKeyProviderCache(master, time.Minute)
	wrapped := []byte("wrapped")

	leaderCtx, cancel := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := cache.ForKey(leaderCtx, "id", wrapped)
		leaderErr <- err
	}()
	<-master.started

	waiterErr := make(chan error, 1)
	go func() {
		_, err := cache.ForKey(context.Background(), "id", wrapped)
		waiterErr <- err
	}()
	time.Sleep(10 * time.Millisecond) // let the waiter join the flight
	cancel()

	if err := <-leaderErr; !errors.Is(err, context.Canceled) {
		t.Errorf("leader err = %v, want context.Canceled", err)
	}
	if err := <-waiterErr; err != nil {
		t.Errorf("waiter failed because the leader was cancelled: %v", err)
	}
}

type panicKP struct{}

func (panicKP) Wrap(context.Context, []byte) ([]byte, error)   { return nil, nil }
func (panicKP) Unwrap(context.Context, []byte) ([]byte, error) { panic("kms client bug") }

// The shared unwrap runs on its own goroutine; a panicking root provider must
// surface as an error to the caller rather than crash the process.
func TestKeyProviderCache_RootPanicBecomesError(t *testing.T) {
	cache := NewKeyProviderCache(panicKP{}, time.Minute)
	if _, err := cache.ForKey(context.Background(), "id", []byte("w")); err == nil {
		t.Fatal("expected an error from a panicking root provider")
	}
}

// gatedKP holds Unwrap until release is closed, then unwraps with a real
// AES-256-GCM master key. The wrapped bytes are therefore read only after the
// caller has already returned.
type gatedKP struct {
	master  *LocalKeyProvider
	release chan struct{}
}

func (g *gatedKP) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	return g.master.Wrap(ctx, dek)
}

func (g *gatedKP) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	<-g.release
	return g.master.Unwrap(ctx, wrapped)
}

// TestKeyProviderCache_CancelledCallerBufferReuse: a caller that gives up while
// the shared unwrap is pending may reuse its buffer. The unwrap must not read
// those bytes, or it caches another key under the digest of the original
// wrapped key.
func TestKeyProviderCache_CancelledCallerBufferReuse(t *testing.T) {
	ctx := context.Background()
	master := NewLocalKeyProvider(makeTestKey(1))
	k1, k2 := makeTestKey(10), makeTestKey(20)
	wrapped1, err := master.Wrap(ctx, k1)
	if err != nil {
		t.Fatal(err)
	}
	wrapped2, err := master.Wrap(ctx, k2)
	if err != nil {
		t.Fatal(err)
	}
	root := &gatedKP{master: master, release: make(chan struct{})}
	cache := NewKeyProviderCache(root, time.Minute)

	buf := bytes.Clone(wrapped1)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := cache.ForKey(cancelled, "id", buf); !errors.Is(err, context.Canceled) {
		t.Fatalf("ForKey err = %v, want context.Canceled", err)
	}
	copy(buf, wrapped2) // the caller reuses its buffer
	close(root.release)

	kp, err := cache.ForKey(ctx, "id", bytes.Clone(wrapped1))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kp.(*LocalKeyProvider).masterKey, k1) {
		t.Fatal("key cached for wrapped1 is not k1: the detached unwrap read the reused buffer")
	}
}
