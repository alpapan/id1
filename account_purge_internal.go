package id1

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// InternalAccountPurgeRequest is the JSON body for POST /internal/account/purge.
type InternalAccountPurgeRequest struct {
	ID string `json:"id"`
}

// HandleInternalAccountPurge returns an HTTP handler for POST /internal/account/purge.
//
// The backend calls it while purging a removed researcher's account. It
// deletes the whole {id} directory - the account key {id}/pub/key, every
// device key under {id}/pub/keys and the salt {id}/priv/salt - in one delete.
//
// The gate is the X-ID1-Internal-Secret header, compared in constant time with
// ID1_INTERNAL_SECRET by validInternalSecret, which refuses every caller when
// the variable is unset (401). The id must match orcidPattern (else 400), so a
// reserved top-level id such as _system can never be named. An id that holds
// nothing gets the same 200 answer, so a purge that is run again gets the same
// result; any other store failure is a 500 and the caller runs the purge again.
//
// main.go_ mounts it only when ID1_INTERNAL_SECRET is set, and it is never on
// the Traefik public route list.
func HandleInternalAccountPurge() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validInternalSecret(r.Header.Get("X-ID1-Internal-Secret")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 64 KiB

		var req InternalAccountPurgeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.ID == "" || !orcidPattern.MatchString(req.ID) {
			http.Error(w, "missing or malformed id", http.StatusBadRequest)
			return
		}

		key, keyErr := KK(req.ID)
		if keyErr != nil {
			http.Error(w, "Failed to purge account", http.StatusInternalServerError)
			return
		}
		if _, err := CmdDel(key).execUnauthorised(); err != nil && !errors.Is(err, ErrNotFound) {
			http.Error(w, "Failed to purge account", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"purged","id":%q}`, req.ID)
	}
}
