package api

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A token that expires while a refresh is in flight must not be returned when
// that refresh fails: the expiry is judged when the failure lands, not when the
// refresh started.
func TestBearerToken_FailedRefreshAfterExpiryDoesNotReturnExpiredToken(t *testing.T) {
	tm := &BearerTokenManager{
		Token:     "old",
		ExpiresAt: time.Now().Add(100 * time.Millisecond),
		Refresher: func(context.Context) (string, time.Time, error) {
			time.Sleep(200 * time.Millisecond)
			return "", time.Time{}, errors.New("idp down")
		},
	}

	tok, err := tm.GetToken(context.Background())
	if err == nil {
		t.Fatalf("GetToken = %q, nil; want the refresh error once the token has expired", tok)
	}
}
