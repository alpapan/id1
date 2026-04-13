package id1

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSyncProxyInvalidURL(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")
	// Unterminated IPv6 bracket causes url.Parse to return an error.
	_, err := SyncProxy("[::1")
	if err == nil {
		t.Error("expected error for invalid target URL")
	}
}

func TestSyncProxyPathStripping(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")
	var capturedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	target := strings.TrimPrefix(upstream.URL, "http://")
	handler, err := SyncProxy(target)
	if err != nil {
		t.Fatalf("SyncProxy error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sync", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if capturedPath != "/" {
		t.Errorf("expected upstream to receive /, got %q", capturedPath)
	}
}

func TestSyncProxyPathWithTrailingSlash(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")
	var capturedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	target := strings.TrimPrefix(upstream.URL, "http://")
	handler, err := SyncProxy(target)
	if err != nil {
		t.Fatalf("SyncProxy error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sync/", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if capturedPath != "/" {
		t.Errorf("expected upstream to receive /, got %q", capturedPath)
	}
}

func TestSyncProxySuccessStatus(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	target := strings.TrimPrefix(upstream.URL, "http://")
	handler, err := SyncProxy(target)
	if err != nil {
		t.Fatalf("SyncProxy error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sync", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestSyncProxyUpstreamUnavailable(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")
	// Use a port that is definitely not listening
	handler, err := SyncProxy("127.0.0.1:19999")
	if err != nil {
		t.Fatalf("SyncProxy error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sync", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected 502 Bad Gateway, got %d", rr.Code)
	}
}

// __END_OF_FILE_MARKER__
