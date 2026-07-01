package id1

import (
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
)

// InternalRegisterRequest is the JSON body for POST /internal/sovereign/register.
type InternalRegisterRequest struct {
	ID           string `json:"id"`
	PublicKeyPEM string `json:"publicKeyPem"`
}

// HandleInternalRegisterKey returns an HTTP handler for POST /internal/sovereign/register.
//
// Trusted-provisioner endpoint, gated by the X-ID1-Internal-Secret header (same gate
// shape as /internal/nc-token). It writes - and OVERWRITES - the singular, no-TTL
// {id}/pub/key. The write goes through CmdSet directly, bypassing the generic auth()
// gate (whose anonymous-write exemption only fires when !idExists), so the trusted
// caller can both provision a new identity and rotate an existing one's key.
//
// This is the seam curatorium uses to provision/rotate a per-user annot8r identity:
// id1's owner-write auth is HMAC-only and rejects an RS256 sovereign JWT, so a holder
// of the user's private key cannot overwrite {id}/pub/key by minting. The shared
// internal secret (held only by the trusted curatorium backend) authorises it instead.
//
// The endpoint is DISABLED when internalSecret is empty: main.go_ should only register
// it when ID1_INTERNAL_SECRET is set, and the handler additionally fails closed so a
// naive empty-header == empty-secret match can never authorise a write.
func HandleInternalRegisterKey(internalSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if internalSecret == "" {
			http.Error(w, "endpoint disabled", http.StatusNotFound)
			return
		}
		if subtle.ConstantTimeCompare(
			[]byte(r.Header.Get("X-ID1-Internal-Secret")),
			[]byte(internalSecret),
		) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Cap the body: it is a small JSON {id, publicKeyPem}; bound it so a
		// trusted-but-buggy (or compromised) caller cannot stream an oversized body.
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 64 KiB

		var req InternalRegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.ID == "" || !orcidPattern.MatchString(req.ID) {
			http.Error(w, "missing or malformed id", http.StatusBadRequest)
			return
		}
		if req.PublicKeyPEM == "" {
			http.Error(w, "Missing publicKeyPem", http.StatusBadRequest)
			return
		}
		if err := validateRSAPublicKeyPEM(req.PublicKeyPEM); err != nil {
			http.Error(w, "Invalid public key: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Singular service-style path, no TTL: a registered identity persists until
		// rotated. CmdSet overwrites any existing value at the key.
		if _, err := CmdSet(KK(req.ID, "pub", "key"), map[string]string{"x-id": req.ID}, []byte(req.PublicKeyPEM)).Exec(); err != nil {
			http.Error(w, "Failed to store key", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"registered","id":%q}`, req.ID)
	}
}

// validateRSAPublicKeyPEM returns nil iff pemStr is a PEM-encoded RSA public key
// (PKIX "PUBLIC KEY" or PKCS#1 "RSA PUBLIC KEY"). Rejecting non-RSA/garbage here
// surfaces a bad key at provision time rather than as a silent mint failure later.
func validateRSAPublicKeyPEM(pemStr string) error {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return fmt.Errorf("not PEM-encoded")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return fmt.Errorf("not an RSA public key")
		}
		return nil
	}
	if _, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return nil
	}
	return fmt.Errorf("unparseable public key")
}
