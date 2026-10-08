package api

import (
	"context"
	"errors"
	"sync"
	"time"
)

const tokenRefreshBufferKey contextKey = "tokenRefreshBuffer"

// WithTokenRefreshBuffer overrides the signed offset added to the token's
// expiry when deciding to refresh. Negative values refresh early (e.g. -10m);
// zero refreshes at expiry, and positive values delay refresh past expiry.
// The default offset is -5m.
func WithTokenRefreshBuffer(ctx context.Context, value time.Duration) context.Context {
	return context.WithValue(ctx, tokenRefreshBufferKey, value)
}

type BearerTokenRefresher func(context.Context) (string, time.Time, error)

type BearerTokenManager struct {
	sync.RWMutex
	Token     string
	ExpiresAt time.Time
	Refresher BearerTokenRefresher
}

// fresh reports whether the held token is still usable. The caller holds the
// lock. Both the fast path and the re-check under the write lock use this one
// predicate, so a token can never be judged stale by one and fresh by the
// other (which, at the exact boundary, returned an expired token).
func (tm *BearerTokenManager) fresh(buffer time.Duration) bool {
	return time.Now().Before(tm.ExpiresAt.Add(buffer))
}

func (tm *BearerTokenManager) GetToken(ctx context.Context) (string, error) {
	bufferDuration, ok := ctx.Value(tokenRefreshBufferKey).(time.Duration)
	if !ok {
		bufferDuration = -5 * time.Minute // default to refresh token 5 mins before expiry
	}
	tm.RLock()
	if tm.fresh(bufferDuration) {
		token := tm.Token
		tm.RUnlock()
		return token, nil
	}
	tm.RUnlock()

	tm.Lock()
	defer tm.Unlock()
	if !tm.fresh(bufferDuration) {
		if tm.Refresher == nil {
			return "", errors.New("api: bearer token expired and no refresher configured")
		}
		token, expiresAt, err := tm.Refresher(ctx)
		if err != nil {
			return "", err
		}
		tm.Token = token
		tm.ExpiresAt = expiresAt
	}
	return tm.Token, nil
}
