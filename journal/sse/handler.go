// Package sse exposes a generic Server-Sent-Events handler over any
// journal.Source — the symmetric read counterpart to journal.Sink for the
// "watch this audit log live in a browser" use case.
//
// Wire shape: each Msg becomes one SSE event with `id: <seq>` and one or
// more `data:` fields. Payloads are UTF-8 text; CRLF and CR line endings are
// normalized to LF, and each line is framed separately so payload text cannot
// inject SSE fields. Binary payloads must be encoded (for example, as
// base64) before publishing. Producers using journal.NewJSONSink[T] already
// publish wire-ready JSON. SSE comments (`: ping`) are written at the
// configured Heartbeat interval to keep proxy connections warm.
//
// Reconnect: browsers' EventSource auto-reconnects with the last seen
// id in the Last-Event-ID header. The handler reads that header and
// resumes via journal.Source.Subscribe with startFromSeq = id+1, so a
// brief network drop doesn't replay the full backfill window.
//
// Auth: the handler is auth-agnostic. Each app wraps it with its own
// session middleware (e.g. portalAdminAuth in auth/vault).
package sse

import (
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/journal"
)

// DefaultReplay is the backfill window used when Handler.Replay is zero.
const DefaultReplay = 100

// DefaultHeartbeat is the keep-alive interval used when Handler.Heartbeat
// is zero. 30s is comfortably under typical proxy idle timeouts (60–90s)
// while not flooding the connection.
const DefaultHeartbeat = 30 * time.Second

// DefaultWriteTimeout bounds each write+flush to a client when
// Handler.WriteTimeout is zero.
const DefaultWriteTimeout = 10 * time.Second

// Handler streams journal.Msg records to a browser as Server-Sent Events.
// Zero values for Replay and Heartbeat fall back to DefaultReplay /
// DefaultHeartbeat. A nil Source panics on first request — wire one
// before installing.
type Handler struct {
	Source    journal.Source
	Replay    int
	Heartbeat time.Duration
	// Done, when non-nil, ends every stream once closed. http.Server.Shutdown
	// does not cancel request contexts, so without it an open stream holds a
	// graceful shutdown until its timeout; pass a channel closed when the
	// server begins shutting down (e.g. ctx.Done() of the run.Group).
	Done <-chan struct{}
	// Limits, when non-nil, caps concurrent streams (globally and/or per
	// client); a request over a cap gets 429 with Retry-After before any
	// transport consumer is created. Note that browsers' EventSource does not
	// reconnect after a non-200 response, so size the caps above what a
	// client legitimately needs.
	Limits *Limits
	// WriteTimeout bounds each write (event or heartbeat) to the client, so a
	// reader that stops draining its socket cannot hold a stream and its
	// transport consumer open forever. Zero ⇒ [DefaultWriteTimeout]; negative
	// disables the per-write deadline. Only effective when the underlying
	// ResponseWriter supports write deadlines (net/http's does, including
	// through wrappers that implement Unwrap).
	WriteTimeout time.Duration
	// Log receives refusals and subscription failures. nil ⇒ slog.Default().
	Log *slog.Logger
}

// ServeHTTP implements http.Handler. Returns 500 if the response writer
// doesn't support flushing, 503 if the Source rejects the subscription,
// otherwise streams until the client disconnects.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := w.(http.Flusher); !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	log := h.Log
	if log == nil {
		log = slog.Default()
	}
	release, scope, ok := h.Limits.acquire(r)
	if !ok {
		log.WarnContext(r.Context(), "journal SSE stream refused: limit reached", "scope", string(scope), "path", r.URL.Path)
		h.Limits.reject(w)
		return
	}
	defer release()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Disable nginx's response buffering so events flush per-message.
	// Harmless when no nginx is in front; required when there is.
	w.Header().Set("X-Accel-Buffering", "no")

	replay := h.Replay
	if replay == 0 {
		replay = DefaultReplay
	}
	heartbeat := h.Heartbeat
	if heartbeat == 0 {
		heartbeat = DefaultHeartbeat
	}

	// Last-Event-ID resume: browsers send this header on reconnect with the
	// id of the last successfully-delivered event. Resume from id+1 so we
	// neither skip nor replay it. A malformed value is treated as "no
	// resume" — fall through to the backfill window.
	var startFromSeq uint64
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n < math.MaxUint64 { // n+1 must not wrap to 0
			startFromSeq = n + 1
		}
	}

	msgs, err := h.Source.Subscribe(r.Context(), replay, startFromSeq)
	if err != nil {
		log.WarnContext(r.Context(), "journal SSE subscription failed", "err", err)
		http.Error(w, "subscribe failed", http.StatusServiceUnavailable)
		return
	}

	writeTimeout := h.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = DefaultWriteTimeout
	}
	rc := http.NewResponseController(w)
	// arm sets a fresh write deadline; call it before each write, since a
	// large event can block on the socket before the flush. The deadline is
	// best-effort: ErrNotSupported just leaves the write unbounded.
	arm := func() {
		if writeTimeout > 0 {
			_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
		}
	}
	// flush pushes buffered output to the client; an error means the client
	// is gone or too slow and the stream must end.
	flush := func() error {
		arm()
		return rc.Flush()
	}

	// Leave a fresh deadline in place on the way out: the last armed one has
	// usually expired by now, which would make net/http fail to write the
	// response terminator and drop a connection that could be reused.
	defer arm()

	if err := flush(); err != nil { // emit headers immediately so the client knows we're alive
		return
	}

	var ticker *time.Ticker
	var tickC <-chan time.Time
	if heartbeat > 0 {
		ticker = time.NewTicker(heartbeat)
		defer ticker.Stop()
		tickC = ticker.C
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case <-h.Done:
			return
		case <-tickC:
			// SSE comment line — clients ignore it; proxies see traffic.
			arm()
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			if err := flush(); err != nil {
				return
			}
		case m, ok := <-msgs:
			if !ok {
				return
			}
			arm()
			if err := writeSSEEvent(w, m); err != nil {
				return
			}
			if err := flush(); err != nil {
				return
			}
		}
	}
}

func writeSSEEvent(w http.ResponseWriter, m journal.Msg) error {
	if _, err := fmt.Fprintf(w, "id: %d\n", m.Seq); err != nil {
		return err
	}
	data := strings.ReplaceAll(string(m.Data), "\r\n", "\n")
	data = strings.ReplaceAll(data, "\r", "\n")
	for line := range strings.SplitSeq(data, "\n") {
		if _, err := fmt.Fprintf(w, "data: %s\n", line); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, "\n")
	return err
}
