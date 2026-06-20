// Package ratelimit is a per-source-IP token-bucket HTTP middleware: baseline
// defense-in-depth for any workload that exposes an API.
//
// It is per-instance and in-process — it throttles abuse from a single source
// (brute-force, credential stuffing, single-client resource exhaustion against
// an expensive auth path or signer, and automated scanning/fuzzing that hunts
// for exploitable bugs). It is NOT a volumetric-DoS control: a distributed
// flood from many IPs bypasses per-IP limits, replicas don't coordinate, and
// L3/L4 floods never reach the application — those belong to an upstream
// LB/WAF/CDN. Nor is it an exploit (e.g. RCE) mitigation; it only slows the
// probing that precedes one.
//
// The limiter is keyed on the immediate TCP peer (r.RemoteAddr), never a raw
// X-Forwarded-For — so the key can't be spoofed by a client-supplied header.
// X-Forwarded-For is consulted only when the peer is itself a configured
// trusted proxy, in which case the rightmost hop that is NOT trusted (the real
// client as seen by infrastructure we control) becomes the key.
package ratelimit

import (
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// idleTTL is how long an idle bucket survives before a sweep evicts it —
	// long enough to span a cert-agentd renewal gap, short enough to bound
	// memory against a stream of distinct source keys.
	idleTTL = 15 * time.Minute
	// sweepInterval throttles the opportunistic GC: at most one pass per
	// interval, run lazily when a new key is first seen — no background
	// goroutine to start, stop, or leak.
	sweepInterval = 5 * time.Minute
)

// Config wires a [Limiter].
type Config struct {
	// RPS is the per-source requests/second. <= 0 disables rate limiting:
	// [New] returns nil and [Limiter.Middleware] passes through.
	RPS float64

	// Burst is the token-bucket burst — requests absorbed instantly before
	// throttling. < 1 ⇒ 1.
	Burst int

	// TrustedProxies are reverse-proxy CIDRs whose X-Forwarded-For is trusted
	// for keying. Empty ⇒ X-Forwarded-For is ignored and the peer IP is the
	// key, so the header can't be used to evade the limit.
	TrustedProxies []*net.IPNet

	// Log receives a Warn line per throttled request. nil ⇒ slog.Default.
	Log *slog.Logger

	// OnThrottle renders the response for a throttled request. The Retry-After
	// header is already set when it runs, so a handler may write any status,
	// body, and Content-Type it likes (e.g. JSON for API clients, HTML for
	// browsers). nil ⇒ a plain-text 429 via [http.Error].
	OnThrottle http.HandlerFunc
}

// Limiter is a per-source-IP token-bucket limiter. The zero value is unusable;
// build with [New].
type Limiter struct {
	rps        rate.Limit
	burst      int
	trusted    []*net.IPNet
	log        *slog.Logger
	onThrottle http.HandlerFunc

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

// bucket is one source's token bucket plus its last-seen time, used to evict
// idle entries so a stream of distinct keys can't grow the map without bound.
type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// New builds a limiter allowing RPS requests/second per source with the given
// burst. Returns nil when RPS <= 0 — a nil *Limiter is a valid no-op whose
// Middleware passes through, so callers can wire it unconditionally.
func New(cfg Config) *Limiter {
	if cfg.RPS <= 0 {
		return nil
	}
	if cfg.Burst < 1 {
		cfg.Burst = 1
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Limiter{
		rps:        rate.Limit(cfg.RPS),
		burst:      cfg.Burst,
		trusted:    cfg.TrustedProxies,
		log:        log,
		onThrottle: cfg.OnThrottle,
		buckets:    make(map[string]*bucket),
	}
}

// Middleware wraps next with per-source-IP token-bucket limiting. A nil Limiter
// (rate limiting disabled) returns next unchanged. Paths in exempt (exact
// match) bypass the limiter — pass "/healthz" so monitoring probes are never
// throttled. A throttled request gets a Retry-After header and is rendered by
// Config.OnThrottle, defaulting to a plain-text 429.
func (l *Limiter) Middleware(next http.Handler, exempt ...string) http.Handler {
	if l == nil {
		return next
	}
	exemptSet := make(map[string]struct{}, len(exempt))
	for _, p := range exempt {
		exemptSet[p] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := exemptSet[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}
		key := l.key(r)
		if !l.allow(key, time.Now()) {
			w.Header().Set("Retry-After", l.retryAfter())
			l.log.Warn("rate limit exceeded", "source", key, "path", r.URL.Path)
			if l.onThrottle != nil {
				l.onThrottle(w, r)
			} else {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allow reports whether a request from key may proceed, consuming a token. now
// is passed in (rather than read internally) so tests can drive time.
func (l *Limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	b, ok := l.buckets[key]
	if !ok {
		l.sweepLocked(now)
		b = &bucket{lim: rate.NewLimiter(l.rps, l.burst)}
		l.buckets[key] = b
	}
	b.seen = now
	l.mu.Unlock()
	return b.lim.AllowN(now, 1)
}

// sweepLocked drops idle buckets. The caller holds l.mu. Rate-limited to one
// pass per sweepInterval so it stays O(1) amortized on the hot path.
func (l *Limiter) sweepLocked(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < sweepInterval {
		return
	}
	l.lastSweep = now
	for k, b := range l.buckets {
		if now.Sub(b.seen) > idleTTL {
			delete(l.buckets, k)
		}
	}
}

// key returns the rate-limit key for r: the immediate peer IP, or — when that
// peer is a trusted proxy — the rightmost X-Forwarded-For hop that is not
// itself trusted (the real client as seen by our own edge). Walking
// right-to-left and stopping at the first untrusted hop defeats a client that
// pre-seeds X-Forwarded-For to spoof its source.
func (l *Limiter) key(r *http.Request) string {
	peer := hostOnly(r.RemoteAddr)
	if len(l.trusted) == 0 || !l.isTrusted(peer) {
		return peer
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if ip != "" && !l.isTrusted(ip) {
			return ip
		}
	}
	return peer
}

func (l *Limiter) isTrusted(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range l.trusted {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// retryAfter is a coarse Retry-After hint (whole seconds, ≥1): the time for one
// token to refill.
func (l *Limiter) retryAfter() string {
	secs := max(int(math.Ceil(1/float64(l.rps))), 1)
	return strconv.Itoa(secs)
}

func hostOnly(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
