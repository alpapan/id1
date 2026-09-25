// apps/backend/containers/id1/sync_ticket_internal.go
//
// group: auth
// tags: sync, websocket, ticket, internal, report-scoped
// summary: Internal report-scoped sync-ticket mint endpoint.
// The Starlette backend calls this once it has already evaluated
// fn_user_can_write_report for a specific report, so id1 - which has no SQL
// driver and cannot compute the verdict itself - mints a ticket carrying the
// report scope and the write verdict the backend already decided.
//
//

package id1

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
)

// syncTicketReportValue is the JSON value stored in the KV for a
// report-scoped sync ticket minted by this route. It differs from
// HandleSyncTicket's plain-subject-bytes value, which the unscoped
// (grid-sync) path still uses; SyncProxy (sync_proxy.go) must parse both
// shapes when it recovers a ticket's value before burning it.
type syncTicketReportValue struct {
	Subject  string `json:"subject"`
	Scope    string `json:"scope"`
	ReportID int64  `json:"report_id"`
	Verdict  string `json:"verdict"`
}

// internalSyncTicketRequest is the JSON body POST /internal/sync_ticket expects.
type internalSyncTicketRequest struct {
	Subject  string `json:"subject"`
	ReportID int64  `json:"report_id"`
	Verdict  string `json:"verdict"`
}

// HandleInternalSyncTicket mints a report-scoped, single-use sync ticket for a
// subject the BACKEND has already cleared to write a specific report.
//
// Auth contract: internal only, never authenticated. The caller MUST present
// a header matching ID1_INTERNAL_SECRET (validInternalSecret, the same gate
// /internal/nc-token and /internal/nc-provision use); a missing or wrong
// header, or an unset server-side secret, is refused with no detail. This
// route is not on Traefik's public route list (apps/id1/CLAUDE.md) and is
// reachable only in-cluster.
//
// A verdict that is not exactly "allowed" (fn_user_can_write_report's other
// two return values are "forbidden" and "frozen") is refused: the route never
// mints a ticket for a subject the backend did not clear to write.
//
// The minted ticket is stored at _syncticket/{ticket} - the SAME KV namespace
// and TTL (syncTicketPrefix, syncTicketTTL) HandleSyncTicket uses, so it is
// swept and single-use-burned identically - but its value is the JSON shape
// syncTicketReportValue rather than a bare subject string.
func HandleInternalSyncTicket(kvStore KeyValueStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validInternalSecret(r.Header.Get("X-ID1-Internal-Secret")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 64 KiB, mirrors sovereign_internal_register.go
		var body internalSyncTicketRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "malformed body", http.StatusBadRequest)
			return
		}
		if body.Subject == "" {
			http.Error(w, "subject required", http.StatusBadRequest)
			return
		}
		if body.ReportID <= 0 {
			http.Error(w, "report_id required", http.StatusBadRequest)
			return
		}
		if body.Verdict != "allowed" {
			http.Error(w, "verdict must be allowed", http.StatusForbidden)
			return
		}

		ticketBytes := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, ticketBytes); err != nil {
			http.Error(w, "failed to generate ticket", http.StatusInternalServerError)
			return
		}
		ticket := base64.RawURLEncoding.EncodeToString(ticketBytes)

		ticketKey, keyErr := KK(syncTicketPrefix, ticket)
		if keyErr != nil {
			http.Error(w, "failed to store ticket", http.StatusInternalServerError)
			return
		}

		value := syncTicketReportValue{
			Subject:  body.Subject,
			Scope:    "report",
			ReportID: body.ReportID,
			Verdict:  body.Verdict,
		}
		valueBytes, err := json.Marshal(value)
		if err != nil {
			http.Error(w, "failed to store ticket", http.StatusInternalServerError)
			return
		}

		if _, err := CmdSet(ticketKey,
			map[string]string{"x-id": syncTicketPrefix, "ttl": syncTicketTTL},
			valueBytes).Exec(); err != nil {
			http.Error(w, "failed to store ticket", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"ticket": ticket})
	}
}

// __END_OF_FILE_MARKER__
