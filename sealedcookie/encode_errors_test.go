package sealedcookie

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A value that cannot be marshalled to JSON must fail to seal. Set must then
// write no cookie at all, rather than an empty or partial one.
func TestSeal_RejectsUnencodableValue(t *testing.T) {
	if _, err := Seal(testKey, make(chan int)); err == nil {
		t.Fatal("Seal accepted a value that cannot be JSON-encoded")
	}
}

func TestSet_RejectsUnencodableValueWithoutWritingCookie(t *testing.T) {
	c := Cookie{Key: testKey, Name: "app_cookie", Path: "/", Now: fixedNow}
	rec := httptest.NewRecorder()
	if err := c.Set(rec, httptest.NewRequest(http.MethodGet, "/", nil), make(chan int), time.Hour); err == nil {
		t.Fatal("Set accepted a value that cannot be JSON-encoded")
	}
	if n := len(rec.Result().Cookies()); n != 0 {
		t.Errorf("a failed Set still wrote %d cookie(s)", n)
	}
}

// A cookie value that is not base64 cannot be a sealed value, so Open must
// reject it before attempting decryption.
func TestOpen_RejectsValueThatIsNotBase64(t *testing.T) {
	var got payload
	if err := Open(testKey, "not base64!!", &got); err == nil {
		t.Fatal("Open accepted a value that is not base64")
	}
}
