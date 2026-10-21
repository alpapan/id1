// apps/id1/error_answer_test.go
//
// group: tests
// tags: errors, http
// summary: What the command handler sends back for a client error and for an internal error.
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

const errorAnswerOrcid = "0000-0000-0009-0035"

// serveWithStore builds the real command handler over storePath and restores
// dbpath when the test ends.
func serveWithStore(t *testing.T, storePath string) func(http.ResponseWriter, *http.Request) {
	t.Helper()
	originalDbpath := dbpath
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		dbpath = originalDbpath
	})
	return Handle(storePath, ctx)
}

func TestErrorAnswer_StoreFailureIs500WithoutTheStorePath(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "store-is-a-file")
	if err := os.WriteFile(storePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write placeholder file: %v", err)
	}
	handler := serveWithStore(t, storePath)

	req := httptest.NewRequest(http.MethodGet, "/"+errorAnswerOrcid+"/pub/x", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500; body=%q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), storePath) {
		t.Fatalf("the answer disclosed the store path: body=%q", rec.Body.String())
	}
	if strings.TrimSpace(rec.Body.String()) != "internal error" {
		t.Fatalf("body: got %q, want %q", rec.Body.String(), "internal error")
	}
}

func TestErrorAnswer_ChallengeFailureIs500WithoutItsText(t *testing.T) {
	storeDir := t.TempDir()
	keyDir := filepath.Join(storeDir, errorAnswerOrcid, "pub", "keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("make key directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "default"), []byte("not a public key"), 0o600); err != nil {
		t.Fatalf("write device key: %v", err)
	}
	handler := serveWithStore(t, storeDir)

	// An unauthenticated read of a key outside pub/ is refused with a challenge
	// built from the account's device key, which here cannot be parsed.
	req := httptest.NewRequest(http.MethodGet, "/"+errorAnswerOrcid+"/notes/x", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500; body=%q", rec.Code, rec.Body.String())
	}
	if strings.TrimSpace(rec.Body.String()) != "internal error" {
		t.Fatalf("body: got %q, want %q", rec.Body.String(), "internal error")
	}
}

func TestErrorAnswer_ClientErrorKeeps400AndItsText(t *testing.T) {
	handler := serveWithStore(t, t.TempDir())

	req := httptest.NewRequest(http.MethodGet, "/"+errorAnswerOrcid+"/pub/*?children=true&recursive=true", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%q", rec.Code, rec.Body.String())
	}
	if strings.TrimSpace(rec.Body.String()) != "recursive can't be true if children is true" {
		t.Fatalf("body: got %q", rec.Body.String())
	}
}
