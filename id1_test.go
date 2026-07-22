// apps/backend/containers/id1/id1_test.go
//
// group: server
// tags: http, server, authorization, testing
// summary: HTTP-level tests for id1.Handle's request wiring.
//
//

package id1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandle_NewIdBootstrapHonoursInternalSecretHeader exercises the real HTTP
// request path (Handle -> NewRequestProps -> auth), not auth() called
// directly. A unit test that calls auth() directly cannot see a mismatch
// between the header name id1.go reads off the request and the one auth()
// expects, or an accidental swap of the auth() call at a different call site;
// this test goes through the same *http.Request parsing production traffic
// does.
func TestHandle_NewIdBootstrapHonoursInternalSecretHeader(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })
	t.Setenv("ID1_INTERNAL_SECRET", "wired-secret")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	handler := Handle(tmpDir, ctx)

	post := func(header string) int {
		req := httptest.NewRequest(http.MethodPost, "/service/pub/key", strings.NewReader(testPubKey1))
		if header != "" {
			req.Header.Set("X-ID1-Internal-Secret", header)
		}
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec.Code
	}

	if code := post(""); code == http.StatusOK {
		t.Fatalf("bootstrap without the header must not succeed via the real HTTP path, got %d", code)
	}
	if code := post("wrong-secret"); code == http.StatusOK {
		t.Fatalf("bootstrap with a wrong header must not succeed via the real HTTP path, got %d", code)
	}
	if code := post("wired-secret"); code != http.StatusOK {
		t.Fatalf("bootstrap with the correct header via the real HTTP path should succeed, got %d", code)
	}
}

// __END_OF_FILE_MARKER__
