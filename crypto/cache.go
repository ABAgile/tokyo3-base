package crypto

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// KeyProviderCache caches per-id intermediate keys to minimise calls to a
// long-lived root KeyProvider (typically a KMS). Use it whenever you have a
// tree of envelope keys — the root wraps N intermediate keys, each of which
// wraps many DEKs. Decrypted intermediate keys stay in memory for ttl; keys
// that are not requested again are dropped once ttl has elapsed and another
// key is cached.
type KeyProviderCache struct {
	rootKP  KeyProvider
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration

	// unwrapFlights collapses concurrent cold misses for the same keyID and
	// wrapped material — when N goroutines miss simultaneously (cold start,
	// post-TTL, or post-Invalidate), only one calls rootKP.Unwrap; the rest
	// piggyback on its result.
	unwrapFlights singleflight.Group
}

// unwrapTimeout bounds one shared rootKP.Unwrap call, which runs detached from
// the callers waiting on it.
const unwrapTimeout = 30 * time.Second

// keyDigest identifies wrapped key material without retaining it.
type keyDigest = [sha256.Size]byte

// cacheEntry is the cached provider for one keyID.
type cacheEntry struct {
	provider *LocalKeyProvider
	// wrappedDigest is the digest of the wrappedKey that produced provider. An
	// entry only answers lookups carrying the same digest, so an unwrap that
	// was in flight during Invalidate (e.g. a key rotation) can never be
	// served to callers that already hold the new wrapped key.
	wrappedDigest keyDigest
	expiresAt     time.Time
}

// NewKeyProviderCache returns a KeyProviderCache backed by rootKP. ttl
// controls how long a decrypted intermediate key stays in memory; pick a
// value that balances root-call cost (longer = fewer calls) against time-
// to-effect after key rotation (shorter = faster recovery). A non-positive
// ttl disables caching.
func NewKeyProviderCache(rootKP KeyProvider, ttl time.Duration) *KeyProviderCache {
	return &KeyProviderCache{
		rootKP:  rootKP,
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
}

// ForKey returns a KeyProvider that wraps/unwraps with the plaintext
// intermediate key for keyID, unwrapping wrappedKey via the root on cache miss.
//
//   - If wrappedKey is nil the root KeyProvider is returned directly. This
//     supports callers that have not yet adopted the intermediate-key layer
//     and still wrap DEKs with the root — they can keep using ForKey
//     uniformly with nil for unmigrated rows.
//   - Otherwise the wrapped key is unwrapped and cached for ttl; subsequent
//     calls for the same keyID within that window skip the root entirely.
//   - A cached key is only returned for the same wrappedKey bytes it was
//     unwrapped from; different bytes for the same keyID are a miss. After
//     rotating a key, callers passing the new wrappedKey therefore never
//     receive the old key, even if an old unwrap finishes late.
func (c *KeyProviderCache) ForKey(ctx context.Context, keyID string, wrappedKey []byte) (KeyProvider, error) {
	if wrappedKey == nil {
		return c.rootKP, nil
	}

	digest := sha256.Sum256(wrappedKey)

	// Fast path: cache hit.
	if kp := c.lookup(keyID, digest); kp != nil {
		return kp, nil
	}

	// Slow path: collapse concurrent misses for the same key and wrapped
	// material into a single rootKP.Unwrap call. The shared call is detached
	// from any one caller's cancellation (and bounded by unwrapTimeout), so a
	// caller that gives up cannot fail the unwrap every other waiter depends
	// on; each caller still stops waiting when its own ctx is done.
	ch := c.unwrapFlights.DoChan(flightKey(keyID, digest), func() (any, error) {
		// Re-check after acquiring the singleflight slot — a previous leader
		// may have populated the cache while we were queued.
		if kp := c.lookup(keyID, digest); kp != nil {
			return kp, nil
		}

		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), unwrapTimeout)
		defer cancel()
		plainKey, err := c.unwrap(uctx, wrappedKey)
		if err != nil {
			return nil, fmt.Errorf("unwrap key: %w", err)
		}
		kp := NewLocalKeyProvider(plainKey)
		c.store(keyID, digest, kp)
		return kp, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		return r.Val.(KeyProvider), nil
	}
}

// unwrap calls the root provider, turning a panic into an error. DoChan runs
// the shared call on its own goroutine, where a panic would take the whole
// process down instead of reaching the caller's recovery (for example
// net/http's per-request recover).
func (c *KeyProviderCache) unwrap(ctx context.Context, wrappedKey []byte) (key []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("root key provider panicked: %v", r)
		}
	}()
	return c.rootKP.Unwrap(ctx, wrappedKey)
}

// flightKey scopes a singleflight call to one keyID and wrapped material, so a
// caller with new material never joins an unwrap of the old one.
func flightKey(keyID string, digest keyDigest) string {
	return keyID + "\x00" + string(digest[:])
}

// lookup returns the live provider cached for keyID that was unwrapped from
// material with the given digest, or nil.
func (c *KeyProviderCache) lookup(keyID string, digest keyDigest) *LocalKeyProvider {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if e, ok := c.entries[keyID]; ok && e.wrappedDigest == digest && time.Now().Before(e.expiresAt) {
		return e.provider
	}
	return nil
}

// store caches provider for keyID until ttl elapses and drops every expired
// entry, so idle keys do not stay resident indefinitely. A non-positive ttl
// disables retention.
func (c *KeyProviderCache) store(keyID string, digest keyDigest, provider *LocalKeyProvider) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, e := range c.entries {
		if !now.Before(e.expiresAt) {
			delete(c.entries, id)
		}
	}
	if c.ttl > 0 {
		c.entries[keyID] = &cacheEntry{provider: provider, wrappedDigest: digest, expiresAt: now.Add(c.ttl)}
	}
}

// Invalidate removes a keyID's cached entry, forcing the next ForKey call to
// re-unwrap from the root. Call this after rotating the underlying key.
func (c *KeyProviderCache) Invalidate(keyID string) {
	c.mu.Lock()
	delete(c.entries, keyID)
	c.mu.Unlock()
}
