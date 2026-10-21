package id1

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// InternalDeregisterRequest is the JSON body for POST /internal/sovereign/deregister.
type InternalDeregisterRequest struct {
	ID     string `json:"id"`
	Device string `json:"device"`
}

// HandleInternalDeregisterKey returns an HTTP handler for POST /internal/sovereign/deregister.
//
// The removal counterpart of HandleInternalRegisterKey, behind the same gate: a
// CA-verified client certificate is required (r.TLS.VerifiedChains non-empty, else
// 401), and the request device must equal the certificate CN (else 403), so a
// curatorium can remove only its own device slot. It deletes {id}/pub/keys/{device}
// and its {device}.name label. A key that is already absent gets the same 200, so a
// caller repeating an interrupted account purge gets the same answer; any other
// store failure is a 500 and the caller repeats the call.
//
// main.go_ mounts it beside the register route under the same
// INTERNAL_REGISTER_ENABLED flag, so it exists only on the dedicated annot8r_id1.
func HandleInternalDeregisterKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 64 KiB

		var req InternalDeregisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.ID == "" || !orcidPattern.MatchString(req.ID) {
			http.Error(w, "missing or malformed id", http.StatusBadRequest)
			return
		}
		if req.Device == "" || !validDeviceID(req.Device) {
			http.Error(w, "missing or malformed device", http.StatusBadRequest)
			return
		}
		// CN-pin: the cert CN is the tenant boundary; a curatorium cannot remove
		// another curatorium's device slot.
		cn := r.TLS.VerifiedChains[0][0].Subject.CommonName
		if req.Device != cn {
			http.Error(w, "device does not match client certificate CN", http.StatusForbidden)
			return
		}

		for _, segment := range []string{req.Device, req.Device + ".name"} {
			key, keyErr := KK(req.ID, "pub", "keys", segment)
			if keyErr != nil {
				http.Error(w, "Failed to remove key", http.StatusInternalServerError)
				return
			}
			if _, err := CmdDel(key).execUnauthorised(); err != nil && !errors.Is(err, ErrNotFound) {
				http.Error(w, "Failed to remove key", http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"deregistered","id":%q,"device":%q}`, req.ID, req.Device)
	}
}
