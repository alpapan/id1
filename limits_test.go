// apps/id1/limits_test.go
//
// group: server
// tags: http, limits, request-body, testing
// summary: Tests that LimitBody caps every route at 64 KiB except the patterns its table raises.
//
//

package id1

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// unsizedBody hides the length of a reader, so httptest gives the request no
// Content-Length, as a chunked upload arrives.
type unsizedBody struct{ io.Reader }

// limitProbe is a mux of three routes whose handlers read the whole body, as
// the real handlers do, and record what they saw.
type limitProbe struct {
	mux     *http.ServeMux
	reached bool
	readLen int
	readErr error
}

func newLimitProbe() *limitProbe {
	p := &limitProbe{mux: http.NewServeMux()}
	handler := func(w http.ResponseWriter, r *http.Request) {
		p.reached = true
		data, err := io.ReadAll(r.Body)
		p.readLen, p.readErr = len(data), err
		w.WriteHeader(http.StatusOK)
	}
	p.mux.HandleFunc("/{key...}", handler)
	p.mux.HandleFunc("/auth/fixed", handler)
	p.mux.HandleFunc("/big/upload", handler)
	return p
}

func (p *limitProbe) post(h http.Handler, path string, body io.Reader) *httptest.ResponseRecorder {
	p.reached, p.readLen, p.readErr = false, 0, nil
	req := httptest.NewRequest(http.MethodPost, path, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func sizedBody(n int64) io.Reader { return bytes.NewReader(make([]byte, n)) }

func unsizedBodyOf(n int64) io.Reader { return unsizedBody{bytes.NewReader(make([]byte, n))} }

func isMaxBytesError(err error) bool {
	var tooLarge *http.MaxBytesError
	return errors.As(err, &tooLarge)
}

// The owner's ruling names the two numbers; this is the one place they are pinned.
func TestLimitBodyConstantsMatchTheOwnerRuling(t *testing.T) {
	if DefaultBodyLimitBytes != 64*1024 {
		t.Errorf("DefaultBodyLimitBytes = %d, want 64 KiB", DefaultBodyLimitBytes)
	}
	if KVBodyLimitBytes != 10*1024*1024 {
		t.Errorf("KVBodyLimitBytes = %d, want 10 MiB", KVBodyLimitBytes)
	}
}

func TestLimitBodyDefaultCapAppliesToARouteTheTableDoesNotName(t *testing.T) {
	p := newLimitProbe()
	h := LimitBody(p.mux, map[string]int64{})

	rec := p.post(h, "/auth/fixed", sizedBody(DefaultBodyLimitBytes))
	if rec.Code != http.StatusOK || !p.reached || int64(p.readLen) != DefaultBodyLimitBytes {
		t.Fatalf("a body exactly at the cap must pass: code %d reached %v read %d", rec.Code, p.reached, p.readLen)
	}

	rec = p.post(h, "/auth/fixed", sizedBody(DefaultBodyLimitBytes+1))
	if rec.Code != http.StatusRequestEntityTooLarge || p.reached {
		t.Fatalf("a declared length one byte over the cap must answer 413 before the handler runs: code %d reached %v", rec.Code, p.reached)
	}
	if rec.Header().Get("Vary") != "Origin" {
		t.Errorf("the 413 must come from err413, which writes the CORS headers; Vary = %q", rec.Header().Get("Vary"))
	}

	p.post(h, "/auth/fixed", unsizedBodyOf(DefaultBodyLimitBytes))
	if p.readErr != nil || int64(p.readLen) != DefaultBodyLimitBytes {
		t.Fatalf("an undeclared length exactly at the cap must pass: read %d err %v", p.readLen, p.readErr)
	}

	p.post(h, "/auth/fixed", unsizedBodyOf(DefaultBodyLimitBytes+1))
	if !p.reached || !isMaxBytesError(p.readErr) || int64(p.readLen) > DefaultBodyLimitBytes {
		t.Fatalf("an undeclared length over the cap must fail the handler's read with *http.MaxBytesError: reached %v read %d err %v", p.reached, p.readLen, p.readErr)
	}
}

func TestLimitBodyLeavesARequestWithNoBodyAlone(t *testing.T) {
	p := newLimitProbe()
	h := LimitBody(p.mux, IngressBodyLimits())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/fixed", nil))
	if rec.Code != http.StatusOK || !p.reached {
		t.Fatalf("a GET with no body must reach the handler: code %d reached %v", rec.Code, p.reached)
	}
}

func TestLimitBodyIngressTableRaisesOnlyTheKeyValueRoute(t *testing.T) {
	p := newLimitProbe()
	h := LimitBody(p.mux, IngressBodyLimits())

	rec := p.post(h, "/some/key", sizedBody(DefaultBodyLimitBytes+1))
	if rec.Code != http.StatusOK || !p.reached {
		t.Fatalf("the key/value route must accept a body over the default cap: code %d reached %v", rec.Code, p.reached)
	}

	rec = p.post(h, "/some/key", sizedBody(KVBodyLimitBytes))
	if rec.Code != http.StatusOK || int64(p.readLen) != KVBodyLimitBytes {
		t.Fatalf("the key/value route must accept a body exactly at its cap: code %d read %d", rec.Code, p.readLen)
	}

	rec = p.post(h, "/some/key", sizedBody(KVBodyLimitBytes+1))
	if rec.Code != http.StatusRequestEntityTooLarge || p.reached {
		t.Fatalf("the key/value route must answer 413 one byte over its cap: code %d reached %v", rec.Code, p.reached)
	}

	p.post(h, "/some/key", unsizedBodyOf(KVBodyLimitBytes+1))
	if !p.reached || !isMaxBytesError(p.readErr) {
		t.Fatalf("an undeclared length over the key/value cap must fail the read with *http.MaxBytesError: reached %v err %v", p.reached, p.readErr)
	}

	rec = p.post(h, "/auth/fixed", sizedBody(DefaultBodyLimitBytes+1))
	if rec.Code != http.StatusRequestEntityTooLarge || p.reached {
		t.Fatalf("a fixed route keeps the default cap although the catch-all is raised: code %d reached %v", rec.Code, p.reached)
	}
}

func TestLimitBodyUncappedPatternHasNoLimit(t *testing.T) {
	p := newLimitProbe()
	h := LimitBody(p.mux, map[string]int64{"/big/upload": BodyUncapped})

	rec := p.post(h, "/big/upload", sizedBody(KVBodyLimitBytes+1))
	if rec.Code != http.StatusOK || int64(p.readLen) != KVBodyLimitBytes+1 {
		t.Fatalf("an uncapped pattern must accept a body over every cap: code %d read %d", rec.Code, p.readLen)
	}

	rec = p.post(h, "/auth/fixed", sizedBody(DefaultBodyLimitBytes+1))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a pattern the table does not name stays capped: code %d", rec.Code)
	}
}
