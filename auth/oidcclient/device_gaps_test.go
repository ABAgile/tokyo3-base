package oidcclient

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// deviceIssuer serves a device_authorization endpoint and a token endpoint, and
// nothing else, so discovery falls back to the convention paths.
func deviceIssuer(t *testing.T, authz, poll http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/device_authorization", authz)
	mux.HandleFunc("/token", poll)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeDeviceError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = io.WriteString(w, `{"error":"`+code+`"}`)
}

func writeDeviceSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"access_token":"at-device","refresh_token":"rt-device","expires_in":3600}`)
}

// noTokenRequest fails the test if the flow reaches the token endpoint when it
// should have stopped earlier.
func noTokenRequest(t *testing.T) http.HandlerFunc {
	return func(http.ResponseWriter, *http.Request) {
		t.Error("the token endpoint should not be reached")
	}
}

// A device_authorization endpoint that drops the connection fails the flow
// before any user is shown a code.
func TestRunDeviceFlow_UnreachableDeviceEndpointFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = RunDeviceFlow(ctx, "http://"+ln.Addr().String(), "cli", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "device_authorization") {
		t.Fatalf("err = %v, want a device_authorization error", err)
	}
}

// A device_authorization response that is not JSON is not a usable code.
func TestRunDeviceFlow_UndecodableDeviceAuthorizationFails(t *testing.T) {
	srv := deviceIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html>not json</html>")
	}, noTokenRequest(t))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := RunDeviceFlow(ctx, srv.URL, "cli", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "decode device_authorization") {
		t.Fatalf("err = %v, want a decode error", err)
	}
}

// A missing interval falls back to five seconds, and a missing expires_in to 900
// seconds. The flow must not treat a missing lifetime as already expired.
func TestRunDeviceFlow_DefaultsIntervalAndExpiry(t *testing.T) {
	sleeps := recordDeviceSleeps(t)
	srv := deviceIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"device_code":"d","user_code":"u","verification_uri":"https://example.test/device"}`)
	}, func(w http.ResponseWriter, _ *http.Request) {
		writeDeviceSuccess(w)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tok, err := RunDeviceFlow(ctx, srv.URL, "cli", io.Discard)
	if err != nil {
		t.Fatalf("RunDeviceFlow: %v", err)
	}
	if tok.AccessToken != "at-device" {
		t.Errorf("AccessToken = %q, want at-device", tok.AccessToken)
	}
	if got := sleeps(); len(got) == 0 || got[0] != 5*time.Second {
		t.Errorf("poll waits = %v, want the 5s default interval first", got)
	}
}

// expires_in bounds the wait for approval. A code still pending when it runs
// out is reported as expired.
func TestRunDeviceFlow_ExpiresWhenNeverApproved(t *testing.T) {
	recordDeviceSleeps(t)
	srv := deviceIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"device_code":"d","user_code":"u","verification_uri":"https://example.test/device","expires_in":1,"interval":1}`)
	}, func(w http.ResponseWriter, _ *http.Request) {
		writeDeviceError(w, "authorization_pending")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := RunDeviceFlow(ctx, srv.URL, "cli", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err = %v, want an expired-code error", err)
	}
}

// Cancelling while the flow waits between polls returns the context error
// promptly, rather than waiting out the interval.
func TestRunDeviceFlow_CancelDuringWaitReturnsContextError(t *testing.T) {
	deviceSleeperMu.Lock()
	original := deviceSleeper
	deviceSleeper = func(time.Duration) <-chan time.Time { return make(chan time.Time) } // never fires
	t.Cleanup(func() {
		deviceSleeper = original
		deviceSleeperMu.Unlock()
	})
	srv := deviceIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"device_code":"d","user_code":"u","verification_uri":"https://example.test/device","expires_in":60,"interval":1}`)
	}, func(w http.ResponseWriter, _ *http.Request) {
		writeDeviceError(w, "authorization_pending")
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := RunDeviceFlow(ctx, srv.URL, "cli", io.Discard)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the flow reach its wait
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the flow kept waiting after cancel")
	}
}
