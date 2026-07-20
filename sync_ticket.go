// apps/backend/containers/id1/sync_ticket.go
//
// group: auth
// tags: sync, websocket, ticket, single-use
// summary: Single-use sync-ticket mint endpoint.
// Exchanges an RS256 JWT for a short-TTL opaque ticket that authenticates the
// header-less /sync WebSocket upgrade (browsers cannot attach an Authorization
// header to a WebSocket handshake).
//
//

package id1

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const (
	// syncTicketPrefix is the id1 KV namespace for in-flight sync tickets. Its Id
	// segment equals syncTicketPrefix so the TTL-scheduled delete self-authorizes in
	// dotAfter (auth(syncTicketPrefix, del) -> Key.Id == syncTicketPrefix), mirroring
	// the _authstate pattern. The leading underscore cannot collide with an ORCID iD.
	syncTicketPrefix = "_syncticket"
	// syncTicketTTL bounds a ticket's lifetime; the frontend mints one immediately
	// before connecting, so a short window is ample and keeps the blast radius small
	// if a ticket ever leaks (it is also single-use - burned on the /sync upgrade).
	syncTicketTTL = "60" // seconds
)

// HandleSyncTicket mints a short-TTL, single-use opaque ticket that the frontend
// uses to authenticate the /sync WebSocket upgrade.
//
// Auth contract: authenticated only. The caller MUST present a valid RS256 id1 JWT
// in the Authorization header (any authenticated user); an anonymous or invalid
// token is rejected 401. The minted ticket is stored in the id1 KV at
// _syncticket/{ticket} with a short TTL and the caller's subject as the value, and
// is single-use (SyncProxy burns it on the upgrade). A leaked ticket is a far
// smaller exposure than a reusable full JWT in a ?token= query string.
func HandleSyncTicket(kvStore KeyValueStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cors(&w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := ValidateRS256JWT(tokenStr, kvStore)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// 32 random bytes -> base64url (URL-safe alphabet: A-Za-z0-9-_, no padding),
		// so the ticket is a single, path-safe KV key segment.
		ticketBytes := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, ticketBytes); err != nil {
			http.Error(w, "Failed to generate ticket", http.StatusInternalServerError)
			return
		}
		ticket := base64.RawURLEncoding.EncodeToString(ticketBytes)

		if _, err := CmdSet(KK(syncTicketPrefix, ticket),
			map[string]string{"x-id": syncTicketPrefix, "ttl": syncTicketTTL},
			[]byte(claims.Subject)).Exec(); err != nil {
			http.Error(w, "Failed to store ticket", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"ticket": ticket})
	}
}

// __END_OF_FILE_MARKER__
