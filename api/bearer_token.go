package api

import (
	"context"
	"errors"
	"fmt"
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

const (
	// refreshTimeout bounds one Refresher call. The call is detached from the
	// caller that triggered it, so one caller's cancellation cannot fail the
	// refresh every other waiter depends on.
	refreshTimeout = 15 * time.Second
	// minRefreshRetry and maxRefreshRetry bound the pause after a failed
	// refresh before the Refresher is called again.
	minRefreshRetry = time.Second
	maxRefreshRetry = 30 * time.Second
)

// BearerTokenManager caches a bearer token and refreshes it through Refresher.
//
// A token inside the refresh window (see [WithTokenRefreshBuffer]) but not yet
// expired is "soft-stale": one caller refreshes it while every other caller
// keeps receiving the current token without waiting, and if the refresh fails
// the current token is still returned until it actually expires. Only a token
// that has expired makes callers wait for the refresh, and its failure is
// returned. After a failed refresh the Refresher is not called again for a
// short, bounded interval, so a broken token endpoint is not hit on every
// request.
type BearerTokenManager struct {
	sync.RWMutex
	Token     string
	ExpiresAt time.Time
	Refresher BearerTokenRefresher

	// OnRefreshError, if set, is called after each failed refresh. tokenStillValid
	// reports whether callers are being served the previous, not-yet-expired
	// token despite the failure. It runs without the manager's lock held but before waiting callers are
	// released, so keep it quick.
	OnRefreshError func(err error, tokenStillValid bool)

	inflight    *refreshCall // guarded by the embedded lock
	nextAttempt time.Time    // earliest next Refresher call after a failure
	lastErr     error        // most recent refresh failure; cleared on success
}

// refreshCall is one in-flight Refresher invocation shared by all waiters.
type refreshCall struct {
	done chan struct{}
	err  error // set before done is closed
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
	if tm.fresh(bufferDuration) {
		token := tm.Token
		tm.Unlock()
		return token, nil
	}
	now := time.Now()
	stale := tm.Token
	usable := stale != "" && now.Before(tm.ExpiresAt) // soft-stale: refresh due, token not expired

	call := tm.inflight
	leader := false
	switch {
	case call != nil:
		// Another caller is already refreshing.
		if usable {
			tm.Unlock()
			return stale, nil
		}
	case tm.Refresher == nil:
		tm.Unlock()
		if usable {
			return stale, nil
		}
		return "", errors.New("api: bearer token expired and no refresher configured")
	case now.Before(tm.nextAttempt):
		// Backing off after a failed refresh.
		lastErr := tm.lastErr
		tm.Unlock()
		if usable {
			return stale, nil
		}
		return "", fmt.Errorf("api: bearer token expired and refresh is backing off: %w", lastErr)
	default:
		call = &refreshCall{done: make(chan struct{})}
		tm.inflight = call
		leader = true
	}
	refresher := tm.Refresher
	tm.Unlock()

	if leader {
		go tm.runRefresh(context.WithoutCancel(ctx), call, refresher)
	}

	select {
	case <-call.done:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if call.err != nil {
		if usable {
			return stale, nil // refresh failed but the previous token has not expired
		}
		return "", call.err
	}
	tm.RLock()
	defer tm.RUnlock()
	return tm.Token, nil
}

// runRefresh performs one Refresher call, stores its outcome, and releases
// every waiter. It owns the in-flight slot until it finishes.
func (tm *BearerTokenManager) runRefresh(ctx context.Context, call *refreshCall, refresher BearerTokenRefresher) {
	ctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()

	token, expiresAt, err := func() (token string, expiresAt time.Time, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("api: bearer token refresher panicked: %v", r)
			}
		}()
		return refresher(ctx)
	}()
	if err == nil && token == "" {
		err = errors.New("api: bearer token refresher returned an empty token")
	}

	tm.Lock()
	now := time.Now()
	if err == nil {
		tm.Token, tm.ExpiresAt = token, expiresAt
		tm.nextAttempt, tm.lastErr = time.Time{}, nil
	} else {
		tm.lastErr = err
		remaining := tm.ExpiresAt.Sub(now)
		tm.nextAttempt = now.Add(min(max(remaining/2, minRefreshRetry), maxRefreshRetry))
	}
	stillValid := tm.Token != "" && now.Before(tm.ExpiresAt)
	onErr := tm.OnRefreshError
	tm.inflight = nil
	call.err = err
	tm.Unlock()

	// Report before releasing waiters so the callback has completed by the time
	// the triggering GetToken returns. It must therefore be quick (log, count).
	if err != nil && onErr != nil {
		func() {
			defer func() { _ = recover() }() // a faulty hook must not wedge waiters
			onErr(err, stillValid)
		}()
	}
	close(call.done)
}
