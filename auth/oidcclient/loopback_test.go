package oidcclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLoopbackListener_BuildsRedirectURI(t *testing.T) {
	listener, redirectURI, err := LoopbackListener(0, "/callback")
	if err != nil {
		t.Fatalf("LoopbackListener: %v", err)
	}
	defer listener.Close()
	if !strings.HasPrefix(redirectURI, "http://127.0.0.1:") || !strings.HasSuffix(redirectURI, "/callback") {
		t.Errorf("redirectURI = %q, want http://127.0.0.1:<port>/callback", redirectURI)
	}
}

func TestLoopbackListener_PortInUse(t *testing.T) {
	hold, _, err := LoopbackListener(0, "/callback")
	if err != nil {
		t.Fatalf("seed LoopbackListener: %v", err)
	}
	defer hold.Close()

	_, portStr, err := net.SplitHostPort(hold.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	_, _, err = LoopbackListener(port, "/callback")
	if err == nil {
		t.Fatal("LoopbackListener: expected error binding an in-use port")
	}
	if !strings.Contains(err.Error(), "loopback listen") {
		t.Errorf("error %q does not name the listen failure source", err.Error())
	}
}

func TestLoopbackCallback_Success(t *testing.T) {
	listener, redirectURI, err := LoopbackListener(0, "/callback")
	if err != nil {
		t.Fatalf("LoopbackListener: %v", err)
	}
	defer listener.Close()

	lc := StartLoopbackCallback(listener, "/callback", func(w http.ResponseWriter, r *http.Request) (string, error) {
		return r.URL.Query().Get("value"), nil
	})

	// StartLoopbackCallback already returned, so the server is serving —
	// no need for a sleep/race before hitting it, unlike a design where
	// serving started only inside a blocking call.
	go func() {
		resp, err := http.Get(redirectURI + "?value=hello")
		if err == nil {
			resp.Body.Close()
		}
	}()

	value, err := lc.Wait(context.Background(), 2*time.Second)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if value != "hello" {
		t.Errorf("value = %q, want hello", value)
	}
}

func TestLoopbackCallback_HandleError(t *testing.T) {
	listener, redirectURI, err := LoopbackListener(0, "/callback")
	if err != nil {
		t.Fatalf("LoopbackListener: %v", err)
	}
	defer listener.Close()

	wantErr := errors.New("boom")
	lc := StartLoopbackCallback(listener, "/callback", func(w http.ResponseWriter, r *http.Request) (string, error) {
		http.Error(w, "boom", http.StatusBadRequest)
		return "", wantErr
	})

	go func() {
		resp, err := http.Get(redirectURI)
		if err == nil {
			resp.Body.Close()
		}
	}()

	_, err = lc.Wait(context.Background(), 2*time.Second)
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

func TestLoopbackCallback_Timeout(t *testing.T) {
	listener, _, err := LoopbackListener(0, "/callback")
	if err != nil {
		t.Fatalf("LoopbackListener: %v", err)
	}
	defer listener.Close()

	lc := StartLoopbackCallback(listener, "/callback", func(w http.ResponseWriter, r *http.Request) (string, error) {
		t.Fatal("handle should never be called — nothing hits the callback")
		return "", nil
	})

	_, err = lc.Wait(context.Background(), 30*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %v, want a timeout error", err)
	}
}

func TestLoopbackCallback_CtxCancel(t *testing.T) {
	listener, _, err := LoopbackListener(0, "/callback")
	if err != nil {
		t.Fatalf("LoopbackListener: %v", err)
	}
	defer listener.Close()

	lc := StartLoopbackCallback(listener, "/callback", func(w http.ResponseWriter, r *http.Request) (string, error) {
		t.Error("handle should never be called — cancelled before any callback")
		return "", nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := lc.Wait(ctx, 5*time.Second)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not exit within 2s of cancel")
	}
}

func TestIsHeadlessSession_LinuxDisplayDetection(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("headless detection only applies on linux")
	}
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	if !isHeadlessSession() {
		t.Error("want headless when DISPLAY and WAYLAND_DISPLAY are both unset")
	}
	t.Setenv("DISPLAY", ":0")
	if isHeadlessSession() {
		t.Error("want not-headless when DISPLAY is set")
	}
}
