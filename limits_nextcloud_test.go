// apps/id1/limits_nextcloud_test.go
//
// group: server
// tags: http, limits, nextcloud, testing
// summary: Tests how the ingress raise table treats the /nextcloud proxy patterns.
//
//

package id1

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

var nextcloudPaths = []string{"/nextcloud", "/nextcloud/remote.php/dav/files/user/result.bin"}

// nextcloudBodyOutcome sends a body of the given size, with a declared length,
// through LimitBody with the ingress raise table, and reports the status and
// how many bytes the handler read.
func nextcloudBodyOutcome(t *testing.T, path string, size int64) (code int, readLen int64) {
	t.Helper()
	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		readLen, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}
	mux.HandleFunc("/{key...}", handler)
	mux.HandleFunc("/nextcloud/", handler)
	mux.HandleFunc("/nextcloud", handler)
	mux.HandleFunc("/auth/refresh", handler)
	rec := httptest.NewRecorder()
	LimitBody(mux, IngressBodyLimits()).ServeHTTP(rec, httptest.NewRequest(http.MethodPut, path, sizedBody(size)))
	return rec.Code, readLen
}

func TestLimitBodyIngressTableDoesNotCapNextcloud(t *testing.T) {
	for _, path := range nextcloudPaths {
		code, read := nextcloudBodyOutcome(t, path, KVBodyLimitBytes+1)
		if code != http.StatusOK || read != KVBodyLimitBytes+1 {
			t.Errorf("%s: a body over every cap must pass uncapped: code %d read %d", path, code, read)
		}
	}
}

// TestLimitBodyIngressTableStillCapsEveryOtherRoute proves the /nextcloud
// exemption is confined to the two Nextcloud patterns: an ordinary route keeps
// the 64 KiB default and the key/value route keeps its 10 MiB cap.
func TestLimitBodyIngressTableStillCapsEveryOtherRoute(t *testing.T) {
	if code, _ := nextcloudBodyOutcome(t, "/auth/refresh", DefaultBodyLimitBytes+1); code != http.StatusRequestEntityTooLarge {
		t.Errorf("/auth/refresh: a body one byte over the default cap must answer 413, got %d", code)
	}
	if code, read := nextcloudBodyOutcome(t, "/auth/refresh", DefaultBodyLimitBytes); code != http.StatusOK || read != DefaultBodyLimitBytes {
		t.Errorf("/auth/refresh: a body exactly at the default cap must pass: code %d read %d", code, read)
	}
	if code, _ := nextcloudBodyOutcome(t, "/nobody/data", KVBodyLimitBytes+1); code != http.StatusRequestEntityTooLarge {
		t.Errorf("/nobody/data: a body one byte over the key/value cap must answer 413, got %d", code)
	}
	if code, _ := nextcloudBodyOutcome(t, "/nextcloudx", KVBodyLimitBytes+1); code != http.StatusRequestEntityTooLarge {
		t.Errorf("/nextcloudx: a path that merely starts with the letters nextcloud is the key/value route and must answer 413 over the key/value cap, got %d", code)
	}
}
