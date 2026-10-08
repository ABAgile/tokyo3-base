package sse

import (
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// DefaultRetryAfter is the Retry-After sent with a 429 when
// [LimitsConfig.RetryAfter] is zero.
const DefaultRetryAfter = 10 * time.Second

// LimitsConfig configures [NewLimits].
type LimitsConfig struct {
	// MaxStreams caps concurrent streams across everything sharing the Limits.
	// 0 = unlimited.
	MaxStreams int
	// MaxPerClient caps concurrent streams per ClientKey value. 0 = unlimited.
	// A browser tab holds one stream, so pick a value above the number of
	// tabs a user realistically keeps open.
	MaxPerClient int
	// ClientKey identifies the client a request belongs to. Required when
	// MaxPerClient > 0. Prefer the authenticated identity (e.g. the session
	// subject); fall back to a source-network key such as
	// clientip.Extractor.NetworkKey. Requests whose key is "" share one
	// bucket, so return a fallback rather than "".
	ClientKey func(*http.Request) string
	// RetryAfter is advertised on a 429. 0 = [DefaultRetryAfter].
	RetryAfter time.Duration
}

// Limits bounds concurrent SSE streams. Every stream costs a transport-level
// consumer (for JetStream, a server-side one), so limiting before Subscribe
// keeps a single client from exhausting the broker. Build with [NewLimits] and
// set it on [Handler.Limits]; one Limits may be shared by several handlers to
// make the caps cover all of them.
type Limits struct {
	cfg LimitsConfig

	mu        sync.Mutex
	total     int
	perClient map[string]int
}

// NewLimits validates cfg and returns a Limits.
func NewLimits(cfg LimitsConfig) (*Limits, error) {
	switch {
	case cfg.MaxStreams < 0 || cfg.MaxPerClient < 0:
		return nil, errors.New("sse: limits must not be negative")
	case cfg.MaxPerClient > 0 && cfg.ClientKey == nil:
		return nil, errors.New("sse: ClientKey is required when MaxPerClient is set")
	}
	if cfg.RetryAfter <= 0 {
		cfg.RetryAfter = DefaultRetryAfter
	}
	return &Limits{cfg: cfg, perClient: make(map[string]int)}, nil
}

// limitScope names which cap rejected a stream, for logging.
type limitScope string

const (
	scopeGlobal limitScope = "global"
	scopeClient limitScope = "client"
)

// acquire reserves a stream slot for r. On success it returns the release
// func (call exactly once). On failure scope says which cap was hit.
func (l *Limits) acquire(r *http.Request) (release func(), scope limitScope, ok bool) {
	if l == nil {
		return func() {}, "", true
	}
	key := ""
	if l.cfg.MaxPerClient > 0 {
		key = l.cfg.ClientKey(r)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cfg.MaxStreams > 0 && l.total >= l.cfg.MaxStreams {
		return nil, scopeGlobal, false
	}
	if l.cfg.MaxPerClient > 0 && l.perClient[key] >= l.cfg.MaxPerClient {
		return nil, scopeClient, false
	}
	l.total++
	if l.cfg.MaxPerClient > 0 {
		l.perClient[key]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			if l.cfg.MaxPerClient > 0 {
				if l.perClient[key]--; l.perClient[key] <= 0 {
					delete(l.perClient, key) // keep the map bounded by live clients
				}
			}
		})
	}, "", true
}

// reject writes the 429 for a refused stream.
func (l *Limits) reject(w http.ResponseWriter) {
	w.Header().Set("Retry-After", strconv.Itoa(int(l.cfg.RetryAfter.Round(time.Second)/time.Second)))
	http.Error(w, "too many event streams", http.StatusTooManyRequests)
}
