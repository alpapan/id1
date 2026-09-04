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
	"os"
	"path/filepath"
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

// TestHandle_DeviceLookupFailureDoesNotLeakRawError exercises the
// unauthenticated challenge path when the device's public key cannot be read
// off disk for a reason other than plain absence (here, a permission
// error), which surfaces a raw *os.PathError - including the on-disk dbpath
// - through CmdGet(deviceKey).Exec(). The response body must never carry
// that raw error text or the filesystem path to an unauthenticated caller.
func TestHandle_DeviceLookupFailureDoesNotLeakRawError(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	deviceKeyDir := filepath.Join(tmpDir, "someid", "pub", "keys")
	if err := os.MkdirAll(deviceKeyDir, 0o755); err != nil {
		t.Fatalf("failed to create device key dir: %v", err)
	}
	deviceKeyPath := filepath.Join(deviceKeyDir, "default")
	if err := os.WriteFile(deviceKeyPath, []byte("unreadable"), 0o644); err != nil {
		t.Fatalf("failed to write device key file: %v", err)
	}
	if err := os.Chmod(deviceKeyPath, 0o000); err != nil {
		t.Fatalf("failed to chmod device key file: %v", err)
	}
	t.Cleanup(func() { os.Chmod(deviceKeyPath, 0o644) })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	handler := Handle(tmpDir, ctx)

	req := httptest.NewRequest(http.MethodGet, "/someid/priv/secretthing", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for the unauthenticated device-lookup-failure path, got %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, tmpDir) {
		t.Fatalf("response body leaked the on-disk dbpath to an unauthenticated caller: %q", body)
	}
	if strings.Contains(body, "permission denied") {
		t.Fatalf("response body leaked the raw filesystem error to an unauthenticated caller: %q", body)
	}
}

// TestHandle_DeviceLookupOrdinaryNotFoundIsNotLogged exercises the same
// unauthenticated challenge path as TestHandle_DeviceLookupFailureDoesNotLeakRawError,
// but for the ordinary case where the device simply has no key registered yet
// (ErrNotFound) - the routine outcome for a brand-new id or a caller that
// omits ?device= against an id with only a singular pub/key. That case must
// not be logged on every anonymous request; only an anomalous lookup failure
// (permission error, disk error, etc.) is worth a server-side log line.
func TestHandle_DeviceLookupOrdinaryNotFoundIsNotLogged(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	getLog := captureLog(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	handler := Handle(tmpDir, ctx)

	req := httptest.NewRequest(http.MethodGet, "/someid/priv/secretthing", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for the unauthenticated no-device-key-yet path, got %d", rec.Code)
	}
	if logged := getLog(); strings.Contains(logged, "device key lookup failed") {
		t.Fatalf("an ordinary not-found device lookup must not be logged, got: %q", logged)
	}
}

// __END_OF_FILE_MARKER__
