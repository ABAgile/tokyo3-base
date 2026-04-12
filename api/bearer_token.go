package api

import (
	"context"
	"sync"
	"time"
)

const tokenRefreshBufferKey contextKey = "tokenRefreshBuffer"

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

func (tm *BearerTokenManager) GetToken(ctx context.Context) (string, error) {
	bufferDuration, ok := ctx.Value(tokenRefreshBufferKey).(time.Duration)
	if !ok {
		bufferDuration = -5 * time.Minute // default to refresh token 5 mins before expiry
	}
	tm.RLock()
	if time.Now().Before(tm.ExpiresAt.Add(bufferDuration)) {
		tm.RUnlock()
		return tm.Token, nil
	}
	tm.RUnlock()

	tm.Lock()
	defer tm.Unlock()
	if time.Now().After(tm.ExpiresAt.Add(bufferDuration)) {
		token, expiresAt, err := tm.Refresher(ctx)
		if err != nil {
			return "", err
		}
		tm.Token = token
		tm.ExpiresAt = expiresAt
	}
	return tm.Token, nil
}
