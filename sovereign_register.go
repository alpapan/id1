// apps/backend/containers/id1/sovereign_register.go
//
// group: auth
// tags: sovereign-keys, registration, device-keys
// summary: Sovereign device key registration and management.
// Two-phase (begin/commit) protocol for registering cryptographic device identities.
//
//

package id1

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const pendingKeyTTL = "3600" // 1 hour
const pubKeyTTL = "604800"  // 7 days — refreshed on every login

// RegisterBeginRequest is the JSON body for POST /auth/sovereign/register/begin.
type RegisterBeginRequest struct {
	PublicKeyPEM string `json:"publicKeyPem"`
	DeviceId     string `json:"deviceId"`
	DeviceName   string `json:"deviceName"`
}

// RegisterBeginResponse is returned on successful begin.
type RegisterBeginResponse struct {
	RegistrationToken string `json:"registrationToken"`
	Challenge         string `json:"challenge"`
	ExpiresIn         int    `json:"expiresIn"`
}

// RegisterCommitRequest is the JSON body for POST /auth/sovereign/register/commit.
type RegisterCommitRequest struct {
	RegistrationToken string `json:"registrationToken"`
	Nonce             string `json:"nonce"`
	DeviceId          string `json:"deviceId"`
	DeviceName        string `json:"deviceName"`
}

// HandleRegisterBegin returns an HTTP handler for Phase 1 of sovereign key registration.
//
// New users (no existing key): anonymous POST accepted.
// Existing users (key already registered): RS256 JWT required in Authorization header.
//
// Stores pending key at {id}/priv/pending/{token}.key with 1-hour TTL.
// Stores nonce at {id}/priv/pending/{token}.nonce with 1-hour TTL.
// Returns encrypted nonce as challenge (RSA-OAEP with the pending public key).
func HandleRegisterBegin(kvStore KeyValueStore) http.HandlerFunc {
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

		orcidId := r.URL.Query().Get("id")
		if orcidId == "" {
			http.Error(w, "Missing id parameter", http.StatusBadRequest)
			return
		}

		var req RegisterBeginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.PublicKeyPEM == "" {
			http.Error(w, "Missing publicKeyPem", http.StatusBadRequest)
			return
		}
		if req.DeviceId == "" {
			http.Error(w, "Missing deviceId", http.StatusBadRequest)
			return
		}

		// Check if user already has any registered device key
		keyExists := idExists(orcidId)

		if keyExists {
			// Re-registration: require RS256 JWT proving ownership
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Key already registered. Provide Authorization header to re-register.", http.StatusConflict)
				return
			}
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := ValidateRS256JWT(tokenStr, kvStore)
			if err != nil {
				http.Error(w, "Invalid JWT: "+err.Error(), http.StatusUnauthorized)
				return
			}
			if claims.Subject != orcidId {
				http.Error(w, "JWT subject does not match requested id", http.StatusForbidden)
				return
			}
		}

		// Generate registration token (32 bytes, URL-safe base64)
		tokenBytes := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}
		token := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(tokenBytes)

		// Generate random nonce (32 bytes)
		nonceBytes := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
			http.Error(w, "Failed to generate nonce", http.StatusInternalServerError)
			return
		}

		// Encrypt nonce with the pending public key (RSA-OAEP)
		challenge, err := encrypt(req.PublicKeyPEM, string(nonceBytes))
		if err != nil {
			http.Error(w, "Invalid public key: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Store pending key + nonce with TTL
		pendingKeyPath := KK(orcidId, "priv", "pending", token+".key")
		pendingNoncePath := KK(orcidId, "priv", "pending", token+".nonce")

		if _, err := CmdSet(pendingKeyPath, map[string]string{"x-id": orcidId, "ttl": pendingKeyTTL}, []byte(req.PublicKeyPEM)).Exec(); err != nil {
			http.Error(w, "Failed to store pending key", http.StatusInternalServerError)
			return
		}
		if _, err := CmdSet(pendingNoncePath, map[string]string{"x-id": orcidId, "ttl": pendingKeyTTL}, nonceBytes).Exec(); err != nil {
			http.Error(w, "Failed to store pending nonce", http.StatusInternalServerError)
			return
		}

		resp := RegisterBeginResponse{
			RegistrationToken: token,
			Challenge:         base64.StdEncoding.EncodeToString(challenge),
			ExpiresIn:         3600,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(resp)
	}
}

// HandleRegisterCommit returns an HTTP handler for Phase 2 of sovereign key registration.
//
// Verifies the decrypted nonce proves private key possession, then promotes the
// pending key to active at {id}/pub/keys/{deviceId}.
//
// Idempotent: if pub/keys/{deviceId} already exists and pending is gone, returns 200 OK.
func HandleRegisterCommit(kvStore KeyValueStore) http.HandlerFunc {
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

		orcidId := r.URL.Query().Get("id")
		if orcidId == "" {
			http.Error(w, "Missing id parameter", http.StatusBadRequest)
			return
		}

		var req RegisterCommitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.DeviceId == "" {
			http.Error(w, "Missing deviceId", http.StatusBadRequest)
			return
		}

		pendingKeyPath := KK(orcidId, "priv", "pending", req.RegistrationToken+".key")
		pendingNoncePath := KK(orcidId, "priv", "pending", req.RegistrationToken+".nonce")

		// Read pending key
		pendingPEM, err := CmdGet(pendingKeyPath).Exec()
		if err != nil || len(pendingPEM) == 0 {
			// Idempotent: if pub/keys/{deviceId} already exists, the commit already went through
			activeKey, activeErr := CmdGet(KK(orcidId, "pub", "keys", req.DeviceId)).Exec()
			if activeErr == nil && len(activeKey) > 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"status":"already_committed","id":"%s"}`, orcidId)
				return
			}
			http.Error(w, "Registration token expired or invalid. Start over.", http.StatusBadRequest)
			return
		}

		// Read expected nonce
		expectedNonce, err := CmdGet(pendingNoncePath).Exec()
		if err != nil || len(expectedNonce) == 0 {
			http.Error(w, "Nonce expired. Start over.", http.StatusBadRequest)
			return
		}

		// Verify nonce (constant-time comparison)
		submittedNonce, err := base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			http.Error(w, "Invalid nonce encoding", http.StatusBadRequest)
			return
		}

		if len(submittedNonce) != len(expectedNonce) {
			http.Error(w, "Nonce verification failed", http.StatusUnauthorized)
			return
		}
		match := true
		for i := range expectedNonce {
			if submittedNonce[i] != expectedNonce[i] {
				match = false
			}
		}
		if !match {
			http.Error(w, "Nonce verification failed", http.StatusUnauthorized)
			return
		}

		// Promote: set pub/keys/{deviceId} = pending PEM with 7-day TTL (refreshed on each login)
		if _, err := CmdSet(KK(orcidId, "pub", "keys", req.DeviceId), map[string]string{"x-id": orcidId, "ttl": pubKeyTTL}, pendingPEM).Exec(); err != nil {
			http.Error(w, "Failed to activate key", http.StatusInternalServerError)
			return
		}

		// Store device name (best-effort, no TTL — lives alongside the key)
		if req.DeviceName != "" {
			CmdSet(KK(orcidId, "pub", "keys", req.DeviceId+".name"), map[string]string{"x-id": orcidId}, []byte(req.DeviceName)).Exec()
		}

		// Clean up pending state (best-effort)
		CmdDel(pendingKeyPath).Exec()
		CmdDel(pendingNoncePath).Exec()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"committed","id":"%s"}`, orcidId)
	}
}
