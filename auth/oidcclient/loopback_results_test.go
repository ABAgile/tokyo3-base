package oidcclient

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoopbackCallback_FirstResultWinsWithoutBlockedDuplicates(t *testing.T) {
	for _, firstError := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "error"}[firstError], func(t *testing.T) {
			ln, url, err := LoopbackListener(0, "/callback")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			var calls atomic.Int32
			wantErr := errors.New("first error")
			lc := StartLoopbackCallback(ln, "/callback", func(w http.ResponseWriter, r *http.Request) (string, error) {
				calls.Add(1)
				if firstError {
					return "", wantErr
				}
				return "first", nil
			})
			client := &http.Client{Timeout: time.Second}
			for i := range 3 {
				resp, err := client.Get(url)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if i > 0 && resp.StatusCode != http.StatusConflict {
					t.Fatalf("duplicate status=%d", resp.StatusCode)
				}
			}
			value, err := lc.Wait(context.Background(), time.Second)
			if firstError && !errors.Is(err, wantErr) {
				t.Fatalf("error=%v", err)
			}
			if !firstError && (value != "first" || err != nil) {
				t.Fatalf("value=%q error=%v", value, err)
			}
			if calls.Load() != 1 {
				t.Fatalf("handler called %d times", calls.Load())
			}
		})
	}
}
func TestLoopbackCallback_ServeFailureIsDelivered(t *testing.T) {
	ln, _, err := LoopbackListener(0, "/callback")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	lc := StartLoopbackCallback(ln, "/callback", func(http.ResponseWriter, *http.Request) (string, error) { return "", nil })
	if _, err := lc.Wait(context.Background(), time.Second); err == nil {
		t.Fatal("closed listener failure was swallowed")
	}
}
