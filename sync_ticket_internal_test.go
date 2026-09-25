// apps/backend/containers/id1/sync_ticket_internal_test.go
//
// group: auth
// tags: sync, ticket, internal, testing
// summary: Tests for the internal report-scoped sync-ticket mint endpoint.
//
//

package id1

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertNoTicketStored fails t if any ticket was written under the
// _syncticket KV namespace - used after a refusal to prove the refusal
// happened before ticket generation, not merely that the response was
// rejected after a ticket had already been minted. Only a not-exist error
// means nothing was written; any other read error (e.g. permissions) is a
// test-environment fault and must fail loud rather than pass silently.
func assertNoTicketStored(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dbpath, syncTicketPrefix))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return
		}
		t.Fatalf("read _syncticket directory: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("ticket stored despite refusal: %v", names)
	}
}

func internalTicketRequestBody(t *testing.T, subject string, reportID int64, verdict string) *bytes.Reader {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"subject":   subject,
		"report_id": reportID,
		"verdict":   verdict,
	})
	require.NoError(t, err)
	return bytes.NewReader(body)
}

// TestInternalSyncTicket_RequiresInternalSecret verifies a request with no
// X-ID1-Internal-Secret header is refused before the body is even read.
func TestInternalSyncTicket_RequiresInternalSecret(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
	req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket",
		internalTicketRequestBody(t, "0000-0001-2345-6789", 42, "allowed"))
	rec := httptest.NewRecorder()
	HandleInternalSyncTicket(kv)(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestInternalSyncTicket_WrongSecret verifies a header present but wrong is
// refused identically to an absent one.
func TestInternalSyncTicket_WrongSecret(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
	req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket",
		internalTicketRequestBody(t, "0000-0001-2345-6789", 42, "allowed"))
	req.Header.Set("X-ID1-Internal-Secret", "wrong")
	rec := httptest.NewRecorder()
	HandleInternalSyncTicket(kv)(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestInternalSyncTicket_UnsetServerSecretRefusesEvenMatchingHeader verifies
// an unset ID1_INTERNAL_SECRET refuses every caller, the same fail-closed
// contract validInternalSecret itself implements - not even an empty header
// against an empty configured secret may match.
func TestInternalSyncTicket_UnsetServerSecretRefusesEvenMatchingHeader(t *testing.T) {
	kv := setupTestKVStore(t)
	req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket",
		internalTicketRequestBody(t, "0000-0001-2345-6789", 42, "allowed"))
	req.Header.Set("X-ID1-Internal-Secret", "")
	rec := httptest.NewRecorder()
	HandleInternalSyncTicket(kv)(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestInternalSyncTicket_RequiresPOST verifies a non-POST method is refused.
func TestInternalSyncTicket_RequiresPOST(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
	req := httptest.NewRequest(http.MethodGet, "/internal/sync_ticket", nil)
	req.Header.Set("X-ID1-Internal-Secret", "s3cret")
	rec := httptest.NewRecorder()
	HandleInternalSyncTicket(kv)(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestInternalSyncTicket_MalformedBody verifies invalid JSON is refused.
func TestInternalSyncTicket_MalformedBody(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
	req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket", bytes.NewReader([]byte("not json")))
	req.Header.Set("X-ID1-Internal-Secret", "s3cret")
	rec := httptest.NewRecorder()
	HandleInternalSyncTicket(kv)(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestInternalSyncTicket_MissingSubject verifies an empty subject is refused.
func TestInternalSyncTicket_MissingSubject(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
	req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket",
		internalTicketRequestBody(t, "", 42, "allowed"))
	req.Header.Set("X-ID1-Internal-Secret", "s3cret")
	rec := httptest.NewRecorder()
	HandleInternalSyncTicket(kv)(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestInternalSyncTicket_MissingReportID verifies a zero/absent report_id is refused.
func TestInternalSyncTicket_MissingReportID(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
	req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket",
		internalTicketRequestBody(t, "0000-0001-2345-6789", 0, "allowed"))
	req.Header.Set("X-ID1-Internal-Secret", "s3cret")
	rec := httptest.NewRecorder()
	HandleInternalSyncTicket(kv)(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestInternalSyncTicket_RefusesNonAllowedVerdict is the load-bearing security
// test: the route never mints a ticket for a subject the backend did not
// clear. "forbidden" and "frozen" (fn_user_can_write_report's own other two
// return values) must both be refused, and no ticket may be stored.
func TestInternalSyncTicket_RefusesNonAllowedVerdict(t *testing.T) {
	for _, verdict := range []string{"forbidden", "frozen", "", "ALLOWED", "Allowed"} {
		kv := setupTestKVStore(t)
		t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
		req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket",
			internalTicketRequestBody(t, "0000-0001-2345-6789", 42, verdict))
		req.Header.Set("X-ID1-Internal-Secret", "s3cret")
		rec := httptest.NewRecorder()
		HandleInternalSyncTicket(kv)(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "verdict %q must be refused", verdict)
		assertNoTicketStored(t)
	}
}

// TestInternalSyncTicket_MintsReportScopedTicket verifies a valid request
// mints a ticket whose stored KV value is the report-scoped JSON shape:
// {"subject":...,"scope":"report","report_id":...,"verdict":"allowed"}.
func TestInternalSyncTicket_MintsReportScopedTicket(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
	req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket",
		internalTicketRequestBody(t, "0000-0001-2345-6789", 42, "allowed"))
	req.Header.Set("X-ID1-Internal-Secret", "s3cret")
	rec := httptest.NewRecorder()
	HandleInternalSyncTicket(kv)(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body struct {
		Ticket string `json:"ticket"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.NotEmpty(t, body.Ticket)

	raw, err := CmdGet(mustKK(t, "_syncticket", body.Ticket)).Exec()
	require.NoError(t, err)
	var stored struct {
		Subject  string `json:"subject"`
		Scope    string `json:"scope"`
		ReportID int64  `json:"report_id"`
		Verdict  string `json:"verdict"`
	}
	require.NoError(t, json.Unmarshal(raw, &stored))
	assert.Equal(t, "0000-0001-2345-6789", stored.Subject)
	assert.Equal(t, "report", stored.Scope)
	assert.Equal(t, int64(42), stored.ReportID)
	assert.Equal(t, "allowed", stored.Verdict)
}

// TestInternalSyncTicket_BodyCapped verifies an oversized body is rejected
// rather than decoded in full, mirroring TestInternalRegister_BodyCapped in
// sovereign_internal_register_test.go for the sibling internal endpoint.
func TestInternalSyncTicket_BodyCapped(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "s3cret")

	// A subject far over the 64 KiB cap (valid JSON, but the reader truncates).
	huge := make([]byte, 128<<10)
	for i := range huge {
		huge[i] = 'A'
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket",
		internalTicketRequestBody(t, string(huge), 42, "allowed"))
	req.Header.Set("X-ID1-Internal-Secret", "s3cret")
	rec := httptest.NewRecorder()
	HandleInternalSyncTicket(kv)(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("oversized body accepted (got 200); MaxBytesReader cap not enforced")
	}
	assertNoTicketStored(t)
}

// TestInternalSyncTicket_GarbageCollectedByDotAfter verifies the TTL-scheduled
// delete of a report-scoped ticket VALUE (the JSON shape this route stores,
// rather than HandleSyncTicket's plain subject bytes) is still authorized and
// swept by dotAfter - the x-id/TTL scheduling path does not care about the
// value's shape. Mirrors TestSyncTicketGarbageCollectedByDotAfter in
// sync_ticket_test.go, which proves the same property for the unscoped
// route's plain-bytes value; this test seeds the same way (short TTL,
// dotAfter(dbpath) called directly after sleeping past it) but with the
// report-scoped JSON value this route actually produces.
func TestInternalSyncTicket_GarbageCollectedByDotAfter(t *testing.T) {
	setupTestKVStore(t)

	value, err := json.Marshal(syncTicketReportValue{
		Subject: "0000-0001-2345-6789", Scope: "report", ReportID: 42, Verdict: "allowed",
	})
	require.NoError(t, err)

	// Seed a ticket with a 1-second TTL via the same path HandleInternalSyncTicket
	// uses (syncTicketPrefix/syncTicketTTL), but with the report-scoped JSON value.
	if _, err := CmdSet(mustKK(t, syncTicketPrefix, "internal-gc-ticket"),
		map[string]string{"ttl": "1", "x-id": syncTicketPrefix}, value).Exec(); err != nil {
		t.Fatalf("seed with ttl: %v", err)
	}
	if data, err := CmdGet(mustKK(t, syncTicketPrefix, "internal-gc-ticket")).Exec(); err != nil || len(data) == 0 {
		t.Fatal("ticket should be present immediately after seeding")
	}

	// ttdMs = now + 1000 (cmd_set.go); dotAfter only fires once now > ttdMs.
	time.Sleep(1100 * time.Millisecond)
	dotAfter(dbpath)

	if _, err := CmdGet(mustKK(t, syncTicketPrefix, "internal-gc-ticket")).Exec(); err == nil {
		t.Error("expired report-scoped sync ticket was not garbage-collected by dotAfter (check x-id authorization)")
	}
}
