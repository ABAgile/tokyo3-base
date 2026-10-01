package oidcclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func recordDeviceSleeps(t *testing.T) func() []time.Duration {
	t.Helper()
	deviceSleeperMu.Lock()
	original := deviceSleeper
	var mu sync.Mutex
	var sleeps []time.Duration
	deviceSleeper = func(d time.Duration) <-chan time.Time {
		mu.Lock()
		sleeps = append(sleeps, d)
		mu.Unlock()
		return time.After(time.Millisecond)
	}
	t.Cleanup(func() {
		deviceSleeper = original
		deviceSleeperMu.Unlock()
	})
	return func() []time.Duration {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(sleeps)
	}
}

func devicePollServer(t *testing.T, poll http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/device_authorization", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"device_code":"d","user_code":"u","verification_uri":"https://example.test/device","expires_in":60,"interval":1}`)
	})
	mux.HandleFunc("/token", poll)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestRunDeviceFlow_ReadsBodyAfterFlushedHeaders(t *testing.T) {
	recordDeviceSleeps(t)
	srv := devicePollServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
		io.WriteString(w, `{"access_token":"token","expires_in":3600}`)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tokens, err := RunDeviceFlow(ctx, srv.URL, "cli", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "token" {
		t.Fatalf("AccessToken = %q", tokens.AccessToken)
	}
}

func TestRunDeviceFlow_PropagatesBodyReadError(t *testing.T) {
	recordDeviceSleeps(t)
	srv := devicePollServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		io.WriteString(w, `{"access_token":"token"}`) // shorter than Content-Length
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := RunDeviceFlow(ctx, srv.URL, "cli", io.Discard)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("RunDeviceFlow = %v, want body read error", err)
	}
}

func TestRunDeviceFlow_SlowDownAddsFiveSecondsEachTime(t *testing.T) {
	sleeps := recordDeviceSleeps(t)
	var polls atomic.Int32
	srv := devicePollServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if polls.Add(1) <= 2 {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":"slow_down"}`)
			return
		}
		io.WriteString(w, `{"access_token":"token","expires_in":3600}`)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := RunDeviceFlow(ctx, srv.URL, "cli", io.Discard); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{time.Second, 6 * time.Second, 11 * time.Second}
	if got := sleeps(); !slices.Equal(got, want) {
		t.Fatalf("poll intervals = %v, want %v", got, want)
	}
}
