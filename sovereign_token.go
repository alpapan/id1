package id1

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"net/http"
	"time"
)

// sovereignTokenRequest is the JSON body for POST /auth/sovereign/token.
type sovereignTokenRequest struct {
	ID        string `json:"id"`
	DeviceId  string `json:"deviceId"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

// maxTimestampSkew is the maximum allowed difference between the client's
// timestamp and the server's clock. Prevents replay attacks while allowing
// reasonable clock drift (e.g., SLURM job nodes).
const maxTimestampSkew = 5 * time.Minute

// HandleSovereignToken returns an HTTP handler that issues RS256 JWTs to
// clients that prove ownership of a registered sovereign RSA key.
//
// Flow:
//  1. Client POSTs {"id": "<userId>", "timestamp": "<RFC3339>", "signature": "<base64>"}
//  2. Server loads public key from KV store at {id}/pub/key
//  3. Server verifies RSA-SHA256 signature of "{id}:{timestamp}" using that key
//  4. Server checks timestamp is within ±5 minutes of server time
//  5. Server issues RS256 JWT with sub={id} (same signJWT used by ORCID/test endpoints)
//
// The signature payload is "{id}:{timestamp}" encoded as UTF-8, signed with
// RSASSA-PKCS1-v1_5 + SHA-256. This is what `openssl dgst -sha256 -sign` produces.
func HandleSovereignToken(kvStore KeyValueStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			cors(&w)
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req sovereignTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			err400(w, "invalid JSON body")
			return
		}

		if req.ID == "" || req.Timestamp == "" || req.Signature == "" {
			err400(w, "id, timestamp, and signature are required")
			return
		}
		if req.DeviceId == "" {
			req.DeviceId = "default"
		}

		// Parse and validate timestamp
		ts, err := time.Parse(time.RFC3339, req.Timestamp)
		if err != nil {
			err400(w, "timestamp must be RFC3339 format")
			return
		}
		skew := time.Since(ts)
		if math.Abs(skew.Seconds()) > maxTimestampSkew.Seconds() {
			err403(w, "timestamp too far from server time")
			return
		}

		// Load the registered public key for this device
		pubKeyPEM, err := CmdGet(KK(req.ID, "pub", "keys", req.DeviceId)).Exec()
		if err != nil || len(pubKeyPEM) == 0 {
			err404(w, "no public key registered for this id")
			return
		}

		// Parse the PEM public key
		pubKey, err := parsePEMPublicKey(pubKeyPEM)
		if err != nil {
			err500(w, "failed to parse stored public key")
			return
		}

		// Verify the signature
		payload := []byte(req.ID + ":" + req.Timestamp)
		sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
		if err != nil {
			err400(w, "signature must be base64-encoded")
			return
		}

		hash := sha256.Sum256(payload)
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sigBytes); err != nil {
			err403(w, "signature verification failed")
			return
		}

		// Signature valid — refresh this device's TTL (7-day inactivity window)
		deviceKey := KK(req.ID, "pub", "keys", req.DeviceId)
		if existingKey, err := CmdGet(deviceKey).Exec(); err == nil && len(existingKey) > 0 {
			CmdSet(deviceKey, map[string]string{"x-id": req.ID, "ttl": "604800"}, existingKey).Exec()
		}

		// Issue RS256 JWT
		keyID, privKey, err := GetOrCreateSigningKey(kvStore)
		if err != nil {
			err500(w, "failed to get signing key")
			return
		}

		jwtToken, err := signJWT(req.ID, privKey, keyID)
		if err != nil {
			err500(w, "failed to sign JWT")
			return
		}

		cors(&w)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jwt":%q}`, jwtToken)
	}
}

// parsePEMPublicKey parses a PEM-encoded RSA public key (PKIX or PKCS1 format).
func parsePEMPublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKIX first (most common for openssl-generated keys)
	if pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		rsaKey, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key")
		}
		return rsaKey, nil
	}

	// Fall back to PKCS1
	if pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pubKey, nil
	}

	return nil, fmt.Errorf("failed to parse public key (tried PKIX and PKCS1)")
}

// __END_OF_FILE_MARKER__
