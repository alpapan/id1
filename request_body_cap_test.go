// apps/id1/request_body_cap_test.go
//
// group: server
// tags: http, limits, request-body, testing
// summary: Tests that NewRequestProps and Handle refuse a request body over the key/value cap.
//
//

package id1

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewRequestPropsReadsABodyUpToTheKeyValueCap(t *testing.T) {
	data := bytes.Repeat([]byte("a"), int(KVBodyLimitBytes))
	props := NewRequestProps(httptest.NewRequest(http.MethodPost, "/alice/data", bytes.NewReader(data)))
	if props.BodyTooLarge {
		t.Fatal("a body exactly at the key/value cap must not be flagged")
	}
	if len(props.Cmd.Data) != len(data) {
		t.Fatalf("read %d bytes, want %d", len(props.Cmd.Data), len(data))
	}
}

func TestNewRequestPropsFlagsABodyOverTheKeyValueCap(t *testing.T) {
	data := bytes.Repeat([]byte("a"), int(KVBodyLimitBytes)+1)
	props := NewRequestProps(httptest.NewRequest(http.MethodPost, "/alice/data", bytes.NewReader(data)))
	if !props.BodyTooLarge {
		t.Fatal("a body one byte over the key/value cap must be flagged")
	}
	if len(props.Cmd.Data) != 0 {
		t.Fatalf("an over-limit body must not be kept; got %d bytes", len(props.Cmd.Data))
	}
}

func TestNewRequestPropsFlagsASmallerCapReportedByTheReader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/alice/data", strings.NewReader("0123456789"))
	req.Body = http.MaxBytesReader(httptest.NewRecorder(), req.Body, 4)
	props := NewRequestProps(req)
	if !props.BodyTooLarge {
		t.Fatal("a read stopped by http.MaxBytesReader must flag the request")
	}
}

// TestHandleAnswers413BeforeAuthorisation goes through the real handler, so it
// proves the flag set by NewRequestProps turns into a 413 and that the answer
// does not depend on who the caller is.
func TestHandleAnswers413BeforeAuthorisation(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	handler := Handle(tmpDir, ctx)

	over := httptest.NewRequest(http.MethodPost, "/nobody/data", bytes.NewReader(make([]byte, KVBodyLimitBytes+1)))
	rec := httptest.NewRecorder()
	handler(rec, over)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a body over the key/value cap must answer 413, got %d", rec.Code)
	}

	atCap := httptest.NewRequest(http.MethodPost, "/nobody/data", bytes.NewReader(make([]byte, KVBodyLimitBytes)))
	rec = httptest.NewRecorder()
	handler(rec, atCap)
	if rec.Code == http.StatusRequestEntityTooLarge {
		t.Fatal("a body exactly at the key/value cap must not answer 413")
	}
}
