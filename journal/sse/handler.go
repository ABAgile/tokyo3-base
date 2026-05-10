// Package sse exposes a generic Server-Sent-Events handler over any
// journal.Source — the symmetric read counterpart to journal.Sink for the
// "watch this audit log live in a browser" use case.
//
// Wire shape: each Msg becomes one SSE event with `id: <seq>` and
// `data: <msg.Data verbatim>`. The Data is forwarded byte-for-byte so the
// handler is encoding-agnostic — producers using journal.NewJSONSink[T]
// already publish wire-ready JSON. SSE comments (`: ping`) are written at
// the configured Heartbeat interval to keep proxy connections warm.
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
	"net/http"
	"strconv"
	"time"

	"github.com/abagile/tokyo3-base/journal"
)

// DefaultReplay is the backfill window used when Handler.Replay is zero.
const DefaultReplay = 100

// DefaultHeartbeat is the keep-alive interval used when Handler.Heartbeat
// is zero. 30s is comfortably under typical proxy idle timeouts (60–90s)
// while not flooding the connection.
const DefaultHeartbeat = 30 * time.Second

// Handler streams journal.Msg records to a browser as Server-Sent Events.
// Zero values for Replay and Heartbeat fall back to DefaultReplay /
// DefaultHeartbeat. A nil Source panics on first request — wire one
// before installing.
type Handler struct {
	Source    journal.Source
	Replay    int
	Heartbeat time.Duration
}

// ServeHTTP implements http.Handler. Returns 500 if the response writer
// doesn't support flushing, 503 if the Source rejects the subscription,
// otherwise streams until the client disconnects.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
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
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			startFromSeq = n + 1
		}
	}

	msgs, err := h.Source.Subscribe(r.Context(), replay, startFromSeq)
	if err != nil {
		http.Error(w, "subscribe failed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	flusher.Flush() // emit headers immediately so the client knows we're alive

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
		case <-tickC:
			// SSE comment line — clients ignore it; proxies see traffic.
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case m, ok := <-msgs:
			if !ok {
				return
			}
			if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", m.Seq, m.Data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
