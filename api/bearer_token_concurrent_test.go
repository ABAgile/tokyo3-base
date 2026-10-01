package api

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Unlike the cold-cache concurrency test, this interleaves cache hits with
// writes. Run under -race to ensure the fast path reads Token under RLock.
func TestBearerTokenManager_CacheHitsDuringRefresh(t *testing.T) {
	var refreshes int
	tm := &BearerTokenManager{
		Token: "token-initial", ExpiresAt: time.Now().Add(time.Hour),
		Refresher: func(context.Context) (string, time.Time, error) {
			refreshes++ // GetToken serializes refreshes under its write lock.
			return fmt.Sprintf("token-%d", refreshes), time.Now().Add(time.Hour), nil
		},
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			ctx := context.Background()
			if i%2 == 0 {
				ctx = WithTokenRefreshBuffer(ctx, -2*time.Hour) // always refresh
			}
			<-start
			for range 1000 {
				token, err := tm.GetToken(ctx)
				if err != nil || !strings.HasPrefix(token, "token-") {
					t.Errorf("GetToken = %q, %v", token, err)
					return
				}
			}
		})
	}
	close(start)
	wg.Wait()
	if refreshes == 0 {
		t.Fatal("test did not exercise refreshes")
	}
}

func TestBearerTokenManager_PositiveBufferRemainsSignedOffset(t *testing.T) {
	tm := &BearerTokenManager{
		Token: "cached", ExpiresAt: time.Now().Add(-time.Minute),
		Refresher: func(context.Context) (string, time.Time, error) {
			t.Fatal("positive offset must preserve the existing delayed-refresh semantics")
			return "", time.Time{}, nil
		},
	}
	token, err := tm.GetToken(WithTokenRefreshBuffer(context.Background(), 5*time.Minute))
	if err != nil || token != "cached" {
		t.Fatalf("GetToken = %q, %v", token, err)
	}
}
