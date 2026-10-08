package api

import (
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
)

const apiErrorBodyLimit = 64 * 1024

// errorBodyTransport caps error bodies before Resty's buffering. Wrapping
// after client options preserves the caller's configured transport/TLS.
type errorBodyTransport struct {
	base http.RoundTripper
}

func (t errorBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil || resp == nil || resp.StatusCode < http.StatusBadRequest || resp.Body == nil || resp.ContentLength == 0 {
		return resp, err
	}
	body := resp.Body
	var reader io.Reader = body
	var compressed *gzip.Reader
	// Resty decompresses explicitly requested gzip too. Do it here so the
	// limit applies to decoded bytes rather than permitting a gzip bomb.
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		compressed, err = gzip.NewReader(body)
		if errors.Is(err, io.EOF) {
			// An error status with an empty gzip-labelled body: hand the
			// response through (empty) so the caller still sees the status.
			body.Close()
			resp.Body = http.NoBody
			resp.ContentLength = 0
			resp.Header.Del("Content-Encoding")
			return resp, nil
		}
		if err != nil {
			body.Close()
			return nil, err
		}
		reader = compressed
		resp.Header.Del("Content-Encoding")
		resp.Uncompressed = true
	}
	resp.Body = &limitedErrorBody{Reader: io.LimitReader(reader, apiErrorBodyLimit), body: body, compressed: compressed}
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
	return resp, nil
}

func (t errorBodyTransport) CloseIdleConnections() {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if closer, ok := base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type limitedErrorBody struct {
	io.Reader
	body       io.ReadCloser
	compressed *gzip.Reader
}

func (b *limitedErrorBody) Close() error {
	if b.compressed != nil {
		b.compressed.Close()
	}
	return b.body.Close()
}
