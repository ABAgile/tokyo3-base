package api

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithTokenRefreshBuffer(t *testing.T) {
	d := 10 * time.Minute
	ctx := WithTokenRefreshBuffer(context.Background(), d)
	got, ok := ctx.Value(tokenRefreshBufferKey).(time.Duration)
	assert.True(t, ok)
	assert.Equal(t, d, got)
}

func TestBearerTokenManager_GetToken(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	past := time.Now().Add(-1 * time.Hour)

	testCases := []struct {
		name      string
		token     string
		expiresAt time.Time
		refresher BearerTokenRefresher
		ctx       context.Context
		wantToken string
		wantErr   bool
	}{
		{
			name:      "returns cached token when valid",
			token:     "cached",
			expiresAt: future,
			refresher: func(ctx context.Context) (string, time.Time, error) {
				return "refreshed", future, nil
			},
			ctx:       context.Background(),
			wantToken: "cached",
		},
		{
			name:      "refreshes expired token",
			token:     "old",
			expiresAt: past,
			refresher: func(ctx context.Context) (string, time.Time, error) {
				return "new", future, nil
			},
			ctx:       context.Background(),
			wantToken: "new",
		},
		{
			name:      "refreshes when within default 5-min buffer",
			token:     "old",
			expiresAt: time.Now().Add(3 * time.Minute),
			refresher: func(ctx context.Context) (string, time.Time, error) {
				return "new", future, nil
			},
			ctx:       context.Background(),
			wantToken: "new",
		},
		{
			name:      "custom buffer triggers early refresh",
			token:     "old",
			expiresAt: time.Now().Add(8 * time.Minute), // outside 5-min default, inside 10-min custom
			refresher: func(ctx context.Context) (string, time.Time, error) {
				return "new", future, nil
			},
			ctx:       WithTokenRefreshBuffer(context.Background(), -10*time.Minute),
			wantToken: "new",
		},
		{
			name:      "propagates refresher error",
			expiresAt: past,
			refresher: func(ctx context.Context) (string, time.Time, error) {
				return "", time.Time{}, errors.New("refresh failed")
			},
			ctx:     context.Background(),
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tm := &BearerTokenManager{
				Token:     tc.token,
				ExpiresAt: tc.expiresAt,
				Refresher: tc.refresher,
			}
			token, err := tm.GetToken(tc.ctx)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantToken, token)
		})
	}
}

func TestBearerTokenManager_GetToken_Concurrent(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	var refreshCount int
	var mu sync.Mutex

	tm := &BearerTokenManager{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		Refresher: func(ctx context.Context) (string, time.Time, error) {
			mu.Lock()
			defer mu.Unlock()
			refreshCount++
			return "refreshed", future, nil
		},
	}

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			tok, err := tm.GetToken(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, "refreshed", tok)
		})
	}
	wg.Wait()

	mu.Lock()
	count := refreshCount
	mu.Unlock()
	assert.Equal(t, 1, count, "refresher must be called exactly once despite concurrent access")
}
