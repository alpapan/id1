package id1

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// SyncProxy creates a reverse proxy for Automerge WebSocket sync requests.
// target is host:port, e.g. "automerge-sync-server:8100".
// The /sync path prefix is stripped so the sync server receives connections at /.
func SyncProxy(target string) (http.HandlerFunc, error) {
	tlsTransport, _ := BuildTLSTransport()

	scheme := "http"
	if tlsTransport != nil {
		scheme = "https"
	}

	targetURL, err := url.Parse(scheme + "://" + target)
	if err != nil {
		return nil, fmt.Errorf("invalid AUTOMERGE_SYNC_SERVER: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	// FlushInterval -1 = flush immediately after each write. This ensures
	// the HTTP 101 Switching Protocols response is not buffered before the
	// connection transitions to the bidirectional WebSocket tunnel.
	proxy.FlushInterval = -1

	if tlsTransport != nil {
		proxy.Transport = tlsTransport
	}

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		req.URL.Path = strings.TrimPrefix(req.URL.Path, "/sync")
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
		if req.URL.RawPath != "" {
			req.URL.RawPath = strings.TrimPrefix(req.URL.RawPath, "/sync")
			if req.URL.RawPath == "" {
				req.URL.RawPath = "/"
			}
		}
		req.Host = targetURL.Host
		originalDirector(req)
		log.Printf("[sync-proxy] %s %s -> %s%s", req.Method, req.URL.Path, targetURL.Host, req.URL.Path)
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[sync-proxy] Error: %v", err)
		http.Error(w, "Sync service unavailable", http.StatusBadGateway)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}, nil
}

// __END_OF_FILE_MARKER__
