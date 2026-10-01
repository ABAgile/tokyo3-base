package sse_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/journal"
	"github.com/abagile/tokyo3-base/journal/sse"
)

type rejectedSource struct{}

func (rejectedSource) Subscribe(context.Context, int, uint64) (<-chan journal.Msg, error) {
	return nil, errors.New("private stream internal.audit on internal-broker")
}
func (rejectedSource) Close() error { return nil }
func TestHandler_SubscribeErrorDoesNotExposeBackendDetails(t *testing.T) {
	rec := httptest.NewRecorder()
	sse.Handler{Source: rejectedSource{}}.ServeHTTP(rec, httptest.NewRequest("GET", "/events", nil))
	if rec.Code != 503 || strings.Contains(rec.Body.String(), "internal") {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}
