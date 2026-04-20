// apps/backend/containers/id1/sovereign_token_test.go
//
// group: auth
// tags: sovereign-keys, challenge-response, testing
// summary: Tests for sovereign key challenge-response authentication.
//
//

package id1

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testSovereignSetup generates an RSA key pair, registers the public key
// in the KV store at pub/keys/{deviceId}, and returns the private key.
func testSovereignSetup(t *testing.T, userID, deviceId string) *rsa.PrivateKey {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	// Register the public key at per-device path
	key := KK(userID, "pub", "keys", deviceId)
	if _, err := CmdSet(key, map[string]string{"x-id": userID}, pubPEM).Exec(); err != nil {
		t.Fatal(err)
	}

	return privKey
}

// signSovereignPayload creates an RSA-SHA256 signature of payload, base64-encoded.
func signSovereignPayload(t *testing.T, privKey *rsa.PrivateKey, payload string) string {
	t.Helper()
	hash := sha256.Sum256([]byte(payload))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestHandleSovereignToken_ValidSignature(t *testing.T) {
	dbpath = t.TempDir()
	kvStore := ID1KeyValueStore{}

	// Ensure a signing key exists for JWT issuance
	_, signingKey, err := GetOrCreateSigningKey(kvStore)
	if err != nil {
		t.Fatal(err)
	}

	userID := "service"
	deviceId := "default"
	privKey := testSovereignSetup(t, userID, deviceId)

	timestamp := time.Now().UTC().Format(time.RFC3339)
	payload := userID + ":" + timestamp
	signature := signSovereignPayload(t, privKey, payload)

	body := `{"id":"` + userID + `","deviceId":"` + deviceId + `","timestamp":"` + timestamp + `","signature":"` + signature + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler := HandleSovereignToken(kvStore)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	jwtString, ok := resp["jwt"]
	if !ok || jwtString == "" {
		t.Fatal("response missing jwt field")
	}

	// Parse JWT using the signing key's public key (same as ORCID test pattern)
	token, err := jwt.ParseWithClaims(jwtString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			t.Errorf("Expected RS256 signing method, got %v", token.Method)
		}
		return &signingKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("JWT parsing failed: %v", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		t.Fatal("JWT should be valid with RegisteredClaims")
	}

	if claims.Subject != userID {
		t.Errorf("expected sub=%q, got %q", userID, claims.Subject)
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != "curatorium-backend" {
		t.Errorf("expected audience curatorium-backend, got %v", claims.Audience)
	}
	if claims.Issuer != "http://id1-router:8080" {
		t.Errorf("expected issuer http://id1-router:8080, got %s", claims.Issuer)
	}
}

func TestHandleSovereignToken_WrongKey(t *testing.T) {
	dbpath = t.TempDir()
	kvStore := ID1KeyValueStore{}

	userID := "service-wrong"
	deviceId := "default"
	_ = testSovereignSetup(t, userID, deviceId)

	// Sign with a DIFFERENT key pair
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	payload := userID + ":" + timestamp
	signature := signSovereignPayload(t, wrongKey, payload)

	body := `{"id":"` + userID + `","deviceId":"` + deviceId + `","timestamp":"` + timestamp + `","signature":"` + signature + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/token", strings.NewReader(body))
	rec := httptest.NewRecorder()

	HandleSovereignToken(kvStore).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSovereignToken_ExpiredTimestamp(t *testing.T) {
	dbpath = t.TempDir()
	kvStore := ID1KeyValueStore{}

	userID := "service-expired"
	deviceId := "default"
	privKey := testSovereignSetup(t, userID, deviceId)

	// Timestamp 10 minutes ago — outside ±5 min window
	timestamp := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
	payload := userID + ":" + timestamp
	signature := signSovereignPayload(t, privKey, payload)

	body := `{"id":"` + userID + `","deviceId":"` + deviceId + `","timestamp":"` + timestamp + `","signature":"` + signature + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/token", strings.NewReader(body))
	rec := httptest.NewRecorder()

	HandleSovereignToken(kvStore).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSovereignToken_UnknownID(t *testing.T) {
	dbpath = t.TempDir()
	kvStore := ID1KeyValueStore{}

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	payload := "nonexistent-user:" + timestamp
	signature := signSovereignPayload(t, privKey, payload)

	body := `{"id":"nonexistent-user","deviceId":"default","timestamp":"` + timestamp + `","signature":"` + signature + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/token", strings.NewReader(body))
	rec := httptest.NewRecorder()

	HandleSovereignToken(kvStore).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSovereignToken_MissingFields(t *testing.T) {
	dbpath = t.TempDir()
	kvStore := ID1KeyValueStore{}

	body := `{"id":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/token", strings.NewReader(body))
	rec := httptest.NewRecorder()

	HandleSovereignToken(kvStore).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSovereignToken_GetMethodRejected(t *testing.T) {
	dbpath = t.TempDir()
	kvStore := ID1KeyValueStore{}

	req := httptest.NewRequest(http.MethodGet, "/auth/sovereign/token", nil)
	rec := httptest.NewRecorder()

	HandleSovereignToken(kvStore).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// TestHandleSovereignToken_FallbackToSingularPubKey verifies that the handler
// falls back to {id}/pub/key (singular) when {id}/pub/keys/{deviceId} is empty.
// This supports the machine/service identity pattern used by SLURM push-callback
// services (BLAST, annot8r, NCBI, datasets_graph), which bootstrap their key
// via the anonymous POST exemption at auth.go:25 at the singular path only.
func TestHandleSovereignToken_FallbackToSingularPubKey(t *testing.T) {
	dbpath = t.TempDir()
	kvStore := ID1KeyValueStore{}

	if _, _, err := GetOrCreateSigningKey(kvStore); err != nil {
		t.Fatal(err)
	}

	userID := "service"
	deviceId := "default"

	// Generate an RSA keypair and register ONLY at the singular path.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	singularPath := KK(userID, "pub", "key")
	if _, err := CmdSet(singularPath, map[string]string{"x-id": userID}, pubPEM).Exec(); err != nil {
		t.Fatal(err)
	}

	// Confirm the multi-device path is absent so we know the fallback triggered.
	if existing, _ := CmdGet(KK(userID, "pub", "keys", deviceId)).Exec(); len(existing) > 0 {
		t.Fatalf("precondition failed: multi-device path should be empty")
	}

	// Sign a token request.
	timestamp := time.Now().UTC().Format(time.RFC3339)
	payload := userID + ":" + timestamp
	hash := sha256.Sum256([]byte(payload))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.StdEncoding.EncodeToString(sigBytes)

	body := `{"id":"` + userID + `","deviceId":"` + deviceId +
		`","timestamp":"` + timestamp + `","signature":"` + signature + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	HandleSovereignToken(kvStore).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 via fallback to singular path, got %d: %s",
			rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["jwt"] == "" {
		t.Fatal("response missing jwt field")
	}
}

// TestHandleSovereignToken_PrefersMultiDevicePath verifies that when BOTH paths
// have a key, the multi-device path wins. This guards against a future
// regression where an ORCID user might have both a legacy singular key and
// current multi-device keys, and we'd want the current ones to take priority.
func TestHandleSovereignToken_PrefersMultiDevicePath(t *testing.T) {
	dbpath = t.TempDir()
	kvStore := ID1KeyValueStore{}

	if _, _, err := GetOrCreateSigningKey(kvStore); err != nil {
		t.Fatal(err)
	}

	userID := "0000-0001-2345-6789"
	deviceId := "default"

	// Generate TWO distinct keypairs: "singular" and "multi-device".
	singularPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	multiDevPriv := testSovereignSetup(t, userID, deviceId)

	// Register the singular keypair at {id}/pub/key.
	singularDER, err := x509.MarshalPKIXPublicKey(&singularPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	singularPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: singularDER})
	if _, err := CmdSet(KK(userID, "pub", "key"),
		map[string]string{"x-id": userID}, singularPEM).Exec(); err != nil {
		t.Fatal(err)
	}

	// Sign with multi-device key — must succeed.
	timestamp := time.Now().UTC().Format(time.RFC3339)
	signature := signSovereignPayload(t, multiDevPriv, userID+":"+timestamp)

	body := `{"id":"` + userID + `","deviceId":"` + deviceId +
		`","timestamp":"` + timestamp + `","signature":"` + signature + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	HandleSovereignToken(kvStore).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (multi-device path wins), got %d: %s",
			rec.Code, rec.Body.String())
	}

	// Sign with singular key — must fail (multi-device is preferred, so the
	// signature won't match the multi-device public key).
	singularSig := signSovereignPayload(t, singularPriv, userID+":"+timestamp)
	body2 := `{"id":"` + userID + `","deviceId":"` + deviceId +
		`","timestamp":"` + timestamp + `","signature":"` + singularSig + `"}`
	req2 := httptest.NewRequest(http.MethodPost, "/auth/sovereign/token", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()

	HandleSovereignToken(kvStore).ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when signing with singular key while multi-device present, got %d: %s",
			rec2.Code, rec2.Body.String())
	}
}

// __END_OF_FILE_MARKER__
