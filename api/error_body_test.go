package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type bodyTransport struct {
	body       *countedBody
	status     int
	encoding   string
	idleClosed bool
}

func (t *bodyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: t.status, Header: http.Header{"Content-Encoding": {t.encoding}}, Body: t.body, ContentLength: -1, Request: r}, nil
}
func (t *bodyTransport) CloseIdleConnections() { t.idleClosed = true }

type countedBody struct {
	io.Reader
	read   int
	closed bool
}

func (b *countedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}
func (b *countedBody) Close() error { b.closed = true; return nil }

func TestRestyClient_EmptyGzipErrorPreservesStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	err := NewRestClient(srv.URL).R(context.Background(), "GET", "/", nil, RO.WithHeader("Accept-Encoding", "gzip"))
	var ae *APIError
	if !errors.As(err, &ae) || len(ae.Body) != 0 || ae.StatusCode != 500 {
		t.Fatalf("empty compressed error = %v", err)
	}
}

// A body labelled gzip that does not decode must still surface its status and
// raw bytes, not a transport error.
func TestRestyClient_MislabelledGzipErrorKeepsStatusAndBody(t *testing.T) {
	for _, payload := range []string{"boom", "upstream exploded, not gzip at all"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, payload)
		}))
		err := NewRestClient(srv.URL).R(context.Background(), "GET", "/", nil, RO.WithHeader("Accept-Encoding", "gzip"))
		srv.Close()
		var ae *APIError
		if !errors.As(err, &ae) || ae.StatusCode != http.StatusBadGateway || string(ae.Body) != payload {
			t.Fatalf("payload %q: err = %v, want 502 APIError carrying the raw body", payload, err)
		}
	}
}

func TestRestyClient_ErrorReadIsBounded(t *testing.T) {
	b := &countedBody{Reader: strings.NewReader(strings.Repeat("x", 1<<20))}
	tr := &bodyTransport{body: b, status: 500}
	rc := NewRestClient("http://example.test", CO.WithTransport(tr))
	err := rc.R(context.Background(), "GET", "/", nil)
	var ae *APIError
	if !errors.As(err, &ae) || len(ae.Body) != apiErrorBodyLimit {
		t.Fatalf("error=%v body=%v", err, ae)
	}
	if b.read != apiErrorBodyLimit || !b.closed {
		t.Fatalf("read=%d closed=%v", b.read, b.closed)
	}
	rc.GetClient().CloseIdleConnections()
	if !tr.idleClosed {
		t.Fatal("transport idle-connection cleanup was lost")
	}
}

func TestRestyClient_LargeSuccessIsNotTruncated(t *testing.T) {
	value := strings.Repeat("x", 1<<20)
	b := &countedBody{Reader: strings.NewReader(`{"value":"` + value + `"}`)}
	rc := NewRestClient("http://example.test", CO.WithTransport(&bodyTransport{body: b, status: 200}))
	var result struct{ Value string }
	if err := rc.R(context.Background(), "GET", "/", &result); err != nil {
		t.Fatal(err)
	}
	if result.Value != value || !b.closed {
		t.Fatal("large successful response was changed")
	}
}

func TestRestyClient_ExplicitGzipErrorsAreBoundedAfterDecode(t *testing.T) {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Write([]byte(strings.Repeat("x", 1<<20)))
	gz.Close()
	b := &countedBody{Reader: bytes.NewReader(compressed.Bytes())}
	rc := NewRestClient("http://example.test", CO.WithTransport(&bodyTransport{body: b, status: 500, encoding: "gzip"}))
	err := rc.R(context.Background(), "GET", "/", nil, RO.WithHeader("Accept-Encoding", "gzip"))
	var ae *APIError
	if !errors.As(err, &ae) || len(ae.Body) != apiErrorBodyLimit || !b.closed {
		t.Fatalf("error=%v closed=%v", err, b.closed)
	}
	if !bytes.Equal(ae.Body, bytes.Repeat([]byte("x"), apiErrorBodyLimit)) {
		t.Fatal("error body was not decoded")
	}
}
