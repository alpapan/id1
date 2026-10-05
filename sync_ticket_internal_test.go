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
	"strings"
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

// gridTicketRequestBody builds the request body for a grid-scoped internal
// sync-ticket mint: {"subject":...,"scope":"grid","automerge_id":...}. Unlike
// internalTicketRequestBody (report-scope shape: subject/report_id/verdict),
// this omits report_id and verdict entirely - a grid mint must never send them.
func gridTicketRequestBody(t *testing.T, subject, automergeID string) *bytes.Reader {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"subject":      subject,
		"scope":        "grid",
		"automerge_id": automergeID,
	})
	require.NoError(t, err)
	return bytes.NewReader(body)
}

// gridTicketRequestBodyWithFields builds a grid-scoped request body that also
// carries report_id and/or verdict, for the tests proving the route rejects a
// grid mint that smuggles report fields.
func gridTicketRequestBodyWithFields(t *testing.T, subject, automergeID string, reportID int64, verdict string) *bytes.Reader {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"subject":      subject,
		"scope":        "grid",
		"automerge_id": automergeID,
		"report_id":    reportID,
		"verdict":      verdict,
	})
	require.NoError(t, err)
	return bytes.NewReader(body)
}

// validGridAutomergeID is a 24-character base58 string matching
// automergeIDPattern, used as a valid id across the grid-scope tests below.
const validGridAutomergeID = "4NMNbHrKADgnbtGJVXVyubc4"

// TestInternalSyncTicket_MintsGridScopedTicket verifies a valid grid-scoped
// request mints a ticket whose stored KV value carries scope "grid" and the
// automerge_id, with report_id and verdict left at their zero values.
func TestInternalSyncTicket_MintsGridScopedTicket(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
	req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket",
		gridTicketRequestBody(t, "0000-0001-2345-6789", validGridAutomergeID))
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
		Subject     string `json:"subject"`
		Scope       string `json:"scope"`
		ReportID    int64  `json:"report_id"`
		Verdict     string `json:"verdict"`
		AutomergeID string `json:"automerge_id"`
	}
	require.NoError(t, json.Unmarshal(raw, &stored))
	assert.Equal(t, "0000-0001-2345-6789", stored.Subject)
	assert.Equal(t, "grid", stored.Scope)
	assert.Equal(t, int64(0), stored.ReportID)
	assert.Equal(t, "", stored.Verdict)
	assert.Equal(t, validGridAutomergeID, stored.AutomergeID)
}

// TestInternalSyncTicket_GridRejectsNonZeroReportID verifies a grid-scoped
// request carrying a non-zero report_id is refused with no ticket stored -
// a grid mint must never smuggle a report identity.
func TestInternalSyncTicket_GridRejectsNonZeroReportID(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
	req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket",
		gridTicketRequestBodyWithFields(t, "0000-0001-2345-6789", validGridAutomergeID, 42, ""))
	req.Header.Set("X-ID1-Internal-Secret", "s3cret")
	rec := httptest.NewRecorder()
	HandleInternalSyncTicket(kv)(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assertNoTicketStored(t)
}

// TestInternalSyncTicket_GridRejectsNonEmptyVerdict verifies a grid-scoped
// request carrying a non-empty verdict is refused with no ticket stored -
// the write-verdict claim belongs to the report scope only.
func TestInternalSyncTicket_GridRejectsNonEmptyVerdict(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
	req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket",
		gridTicketRequestBodyWithFields(t, "0000-0001-2345-6789", validGridAutomergeID, 0, "allowed"))
	req.Header.Set("X-ID1-Internal-Secret", "s3cret")
	rec := httptest.NewRecorder()
	HandleInternalSyncTicket(kv)(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assertNoTicketStored(t)
}

// TestInternalSyncTicket_GridRejectsBadOrEmptyAutomergeID verifies a grid
// mint with an automerge_id that fails automergeIDPattern (including empty)
// is refused with no ticket stored. Beyond the shape-level cases (empty, too
// short, containing spaces), three cases isolate a single specific fault
// each: a forbidden-character-only fault (a leading '0', which the base58
// alphabet excludes, on an otherwise-valid 24-character id, so a widened
// character class - not the length check - is what must catch it), a
// length-only fault (65 characters, all otherwise-valid base58 characters,
// one over the 64-character ceiling), and an id carrying the "automerge:"
// prefix that must never be included in the stored id.
func TestInternalSyncTicket_GridRejectsBadOrEmptyAutomergeID(t *testing.T) {
	tooLong := strings.Repeat("A", 65)
	badIDs := []string{
		"", "short", "has spaces in it 1234567890",
		"0NMNbHrKADgnbtGJVXVyubc4",           // only fault: leading '0', excluded from the base58 alphabet
		tooLong,                              // only fault: 65 chars, one over the 64-char ceiling
		"automerge:4NMNbHrKADgnbtGJVXVyubc4", // carries the forbidden "automerge:" prefix
	}
	for _, badID := range badIDs {
		kv := setupTestKVStore(t)
		t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
		req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket",
			gridTicketRequestBody(t, "0000-0001-2345-6789", badID))
		req.Header.Set("X-ID1-Internal-Secret", "s3cret")
		rec := httptest.NewRecorder()
		HandleInternalSyncTicket(kv)(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "automerge_id %q must be refused", badID)
		assertNoTicketStored(t)
	}
}

// TestInternalSyncTicket_ReportScopeRejectsAutomergeID verifies a report (or
// default/empty) scope request that also carries a non-empty automerge_id is
// refused - the two scopes' identifying fields must never mix.
func TestInternalSyncTicket_ReportScopeRejectsAutomergeID(t *testing.T) {
	for _, scope := range []string{"", "report"} {
		kv := setupTestKVStore(t)
		t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
		body, err := json.Marshal(map[string]any{
			"subject":      "0000-0001-2345-6789",
			"scope":        scope,
			"report_id":    42,
			"verdict":      "allowed",
			"automerge_id": validGridAutomergeID,
		})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket", bytes.NewReader(body))
		req.Header.Set("X-ID1-Internal-Secret", "s3cret")
		rec := httptest.NewRecorder()
		HandleInternalSyncTicket(kv)(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "scope %q with automerge_id must be refused", scope)
		assertNoTicketStored(t)
	}
}

// TestInternalSyncTicket_RejectsUnknownScope verifies a scope value other
// than "", "report" or "grid" is refused with no ticket stored.
func TestInternalSyncTicket_RejectsUnknownScope(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
	body, err := json.Marshal(map[string]any{
		"subject": "0000-0001-2345-6789",
		"scope":   "bogus",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket", bytes.NewReader(body))
	req.Header.Set("X-ID1-Internal-Secret", "s3cret")
	rec := httptest.NewRecorder()
	HandleInternalSyncTicket(kv)(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assertNoTicketStored(t)
}

// TestInternalSyncTicket_GridTicketValueRoundTrips verifies the JSON value
// this route stores for a grid mint decodes back into syncTicketReportValue
// (the shared shape SyncProxy parses) with automerge_id intact and the report
// fields at their zero values - the round trip SyncProxy depends on.
func TestInternalSyncTicket_GridTicketValueRoundTrips(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_INTERNAL_SECRET", "s3cret")
	req := httptest.NewRequest(http.MethodPost, "/internal/sync_ticket",
		gridTicketRequestBody(t, "0000-0001-2345-6789", validGridAutomergeID))
	req.Header.Set("X-ID1-Internal-Secret", "s3cret")
	rec := httptest.NewRecorder()
	HandleInternalSyncTicket(kv)(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body struct {
		Ticket string `json:"ticket"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	raw, err := CmdGet(mustKK(t, "_syncticket", body.Ticket)).Exec()
	require.NoError(t, err)
	var decoded syncTicketReportValue
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, "0000-0001-2345-6789", decoded.Subject)
	assert.Equal(t, "grid", decoded.Scope)
	assert.Equal(t, int64(0), decoded.ReportID)
	assert.Equal(t, "", decoded.Verdict)
	assert.Equal(t, validGridAutomergeID, decoded.AutomergeID)
}
