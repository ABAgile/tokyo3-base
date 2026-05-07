package crypto

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// KeyProviderCache caches per-id intermediate keys to minimise calls to a
// long-lived master KeyProvider (typically a KMS). Use it whenever you have
// a tree of envelope keys — the master wraps N intermediate keys, each of
// which wraps many DEKs.
//
// ForKey(ctx, keyID, wrappedKey) unwraps wrappedKey via the master on cache
// miss, holds the resulting plaintext key in memory for ttl, and returns a
// KeyProvider that wraps/unwraps with that plaintext key. Subsequent calls
// for the same keyID within ttl skip the master entirely.
//
// `unwrap` is a singleflight.Group that collapses concurrent cold misses for
// the same keyID — when N goroutines miss simultaneously (cold start, post-TTL,
// or post-Invalidate), only one calls master.Unwrap; the rest piggyback on
// its result.
type KeyProviderCache struct {
	master KeyProvider
	mu     sync.RWMutex
	keys   map[string]*cacheEntry
	ttl    time.Duration
	unwrap singleflight.Group
}

type cacheEntry struct {
	kp        *LocalKeyProvider
	expiresAt time.Time
}

// NewKeyProviderCache returns a KeyProviderCache backed by master. ttl
// controls how long a decrypted intermediate key stays in memory; pick a
// value that balances master-call cost (longer = fewer calls) against time-
// to-effect after key rotation (shorter = faster recovery).
func NewKeyProviderCache(master KeyProvider, ttl time.Duration) *KeyProviderCache {
	return &KeyProviderCache{
		master: master,
		keys:   make(map[string]*cacheEntry),
		ttl:    ttl,
	}
}

// ForKey returns a KeyProvider for the given keyID, unwrapping wrappedKey
// via the master on cache miss.
//
//   - If wrappedKey is nil the master KeyProvider is returned directly. This
//     supports callers that have not yet adopted the intermediate-key layer
//     and still wrap DEKs with the master — they can keep using ForKey
//     uniformly with nil for unmigrated rows.
//   - Otherwise the wrapped key is unwrapped and cached for ttl; subsequent
//     calls within that window are free.
func (c *KeyProviderCache) ForKey(ctx context.Context, keyID string, wrappedKey []byte) (KeyProvider, error) {
	if wrappedKey == nil {
		return c.master, nil
	}

	// Fast path: cache hit.
	c.mu.RLock()
	entry, ok := c.keys[keyID]
	if ok && time.Now().Before(entry.expiresAt) {
		kp := entry.kp
		c.mu.RUnlock()
		return kp, nil
	}
	c.mu.RUnlock()

	// Slow path: collapse concurrent misses for the same key into a single
	// master.Unwrap call. The leader runs with its own ctx; waiters share its
	// result (or its error — failure paths dedupe too).
	v, err, _ := c.unwrap.Do(keyID, func() (any, error) {
		// Re-check after acquiring the singleflight slot — a previous leader
		// may have populated the cache while we were queued.
		c.mu.RLock()
		entry, ok := c.keys[keyID]
		c.mu.RUnlock()
		if ok && time.Now().Before(entry.expiresAt) {
			return entry.kp, nil
		}

		plainKey, err := c.master.Unwrap(ctx, wrappedKey)
		if err != nil {
			return nil, fmt.Errorf("unwrap key: %w", err)
		}
		kp := NewLocalKeyProvider(plainKey)
		c.mu.Lock()
		c.keys[keyID] = &cacheEntry{kp: kp, expiresAt: time.Now().Add(c.ttl)}
		c.mu.Unlock()
		return kp, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(KeyProvider), nil
}

// Invalidate removes a keyID's cached entry, forcing the next ForKey call to
// re-unwrap from the master. Call this after rotating the underlying key.
func (c *KeyProviderCache) Invalidate(keyID string) {
	c.mu.Lock()
	delete(c.keys, keyID)
	c.mu.Unlock()
}
