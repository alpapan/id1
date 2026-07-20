// apps/backend/containers/id1/sync_ticket_test.go
//
// group: auth
// tags: sync, ticket, single-use, testing
// summary: Tests for the single-use sync-ticket mint endpoint.
//
//

package id1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSyncTicket_RequiresJWT verifies the mint endpoint refuses an anonymous request:
// only an authenticated caller may obtain a ticket to reach /sync.
func TestSyncTicket_RequiresJWT(t *testing.T) {
	kv := setupTestKVStore(t)
	GetOrCreateSigningKey(kv)
	rec := httptest.NewRecorder()
	HandleSyncTicket(kv)(rec, httptest.NewRequest(http.MethodPost, "/auth/sync_ticket", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "ticket mint requires a valid Bearer JWT")
}

// TestSyncTicket_MintsSingleUseTicket verifies a valid JWT yields a ticket stored in
// the KV under _syncticket/{ticket} with the caller's subject as the value.
func TestSyncTicket_MintsSingleUseTicket(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, privKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)
	tok, err := signJWT("0000-0001-2345-6789", []string{"orcid"}, privKey, keyID)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/auth/sync_ticket", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	HandleSyncTicket(kv)(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		Ticket string `json:"ticket"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.NotEmpty(t, body.Ticket)
	data, err := CmdGet(KK("_syncticket", body.Ticket)).Exec()
	require.NoError(t, err)
	assert.Equal(t, "0000-0001-2345-6789", string(data)) // stored sub
}

// TestSyncTicket_RejectsInvalidToken verifies a garbage bearer token is refused.
func TestSyncTicket_RejectsInvalidToken(t *testing.T) {
	kv := setupTestKVStore(t)
	GetOrCreateSigningKey(kv)
	req := httptest.NewRequest(http.MethodPost, "/auth/sync_ticket", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-jwt")
	rec := httptest.NewRecorder()
	HandleSyncTicket(kv)(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestSyncTicket_GET_405 verifies non-POST is rejected.
func TestSyncTicket_GET_405(t *testing.T) {
	kv := setupTestKVStore(t)
	rec := httptest.NewRecorder()
	HandleSyncTicket(kv)(rec, httptest.NewRequest(http.MethodGet, "/auth/sync_ticket", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestSyncTicketGarbageCollectedByDotAfter verifies the TTL-scheduled delete of a sync
// ticket is authorized (correct x-id) and that dotAfter sweeps an expired ticket off disk.
// This proves the ticket's x-id equals its key's first segment (_syncticket) so the
// TTL self-authorizes; a wrong x-id would leave a "single-use, 60s" ticket KV-resident
// and usable indefinitely, which nothing else here would catch. Mirrors the _authstate
// sibling TestOrcidStateGarbageCollectedByDotAfter.
func TestSyncTicketGarbageCollectedByDotAfter(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	// Seed a ticket with a 1-second TTL via the same path HandleSyncTicket uses.
	if _, err := CmdSet(KK(syncTicketPrefix, "gc-ticket"),
		map[string]string{"ttl": "1", "x-id": syncTicketPrefix},
		[]byte("0000-0001-2345-6789")).Exec(); err != nil {
		t.Fatalf("seed with ttl: %v", err)
	}
	if data, err := CmdGet(KK(syncTicketPrefix, "gc-ticket")).Exec(); err != nil || len(data) == 0 {
		t.Fatal("ticket should be present immediately after seeding")
	}

	// ttdMs = now + 1000 (cmd_set.go); dotAfter only fires once now > ttdMs.
	time.Sleep(1100 * time.Millisecond)
	dotAfter(dbpath)

	if _, err := CmdGet(KK(syncTicketPrefix, "gc-ticket")).Exec(); err == nil {
		t.Error("expired sync ticket was not garbage-collected by dotAfter (check x-id authorization)")
	}
}

// __END_OF_FILE_MARKER__
