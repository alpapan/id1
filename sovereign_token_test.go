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
	key := mustKK(t, userID, "pub", "keys", deviceId)
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

	// Timestamp 10 minutes ago - outside +/-5 min window
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

	singularPath := mustKK(t, userID, "pub", "key")
	if _, err := CmdSet(singularPath, map[string]string{"x-id": userID}, pubPEM).Exec(); err != nil {
		t.Fatal(err)
	}

	// Confirm the multi-device path is absent so we know the fallback triggered.
	if existing, _ := CmdGet(mustKK(t, userID, "pub", "keys", deviceId)).Exec(); len(existing) > 0 {
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
	if _, err := CmdSet(mustKK(t, userID, "pub", "key"),
		map[string]string{"x-id": userID}, singularPEM).Exec(); err != nil {
		t.Fatal(err)
	}

	// Sign with multi-device key - must succeed.
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

	// Sign with singular key - must fail (multi-device is preferred, so the
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

// TestSovereignToken_StampsSovereignAMR verifies the machine/service mint path
// stamps amr=["sovereign"], so the backend never auto-provisions a new user row
// from a self-minted sovereign token.
func TestSovereignToken_StampsSovereignAMR(t *testing.T) {
	dbpath = t.TempDir()
	kvStore := ID1KeyValueStore{}
	if _, _, err := GetOrCreateSigningKey(kvStore); err != nil {
		t.Fatal(err)
	}
	userID := "0000-0001-2345-6789"
	deviceId := "default"
	privKey := testSovereignSetup(t, userID, deviceId)

	timestamp := time.Now().UTC().Format(time.RFC3339)
	signature := signSovereignPayload(t, privKey, userID+":"+timestamp)
	body := `{"id":"` + userID + `","deviceId":"` + deviceId + `","timestamp":"` + timestamp + `","signature":"` + signature + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	HandleSovereignToken(kvStore).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	claims, err := ValidateRS256JWTID1Claims(resp["jwt"], kvStore)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	found := false
	for _, a := range claims.AMR {
		if a == "sovereign" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected amr to contain 'sovereign', got %v", claims.AMR)
	}
}

// hostileSovereignTokenDeviceIdCases is the case list for
// TestHandleSovereignToken_RejectsHostileDeviceId: distinct deviceId shapes
// that devicePattern must reject at the door, before any KV lookup is
// attempted. No production registry names this set, so it is literal and
// asserted below for exact length and membership.
var hostileSovereignTokenDeviceIdCases = []struct {
	name     string
	deviceId string
}{
	{name: "path traversal", deviceId: "../victim/pub/keys/evil"},
	{name: "embedded slash", deviceId: "a/b"},
	{name: "leading dot", deviceId: ".hidden"},
}

func TestHandleSovereignToken_RejectsHostileDeviceIdCaseListIsPopulated(t *testing.T) {
	if len(hostileSovereignTokenDeviceIdCases) != 3 {
		t.Fatalf("expected exactly 3 cases, got %d", len(hostileSovereignTokenDeviceIdCases))
	}
	names := map[string]bool{}
	for _, c := range hostileSovereignTokenDeviceIdCases {
		names[c.name] = true
	}
	for _, want := range []string{"path traversal", "embedded slash", "leading dot"} {
		if !names[want] {
			t.Errorf("hostileSovereignTokenDeviceIdCases is missing case %q", want)
		}
	}
}

// TestHandleSovereignToken_RejectsHostileDeviceId is the load-bearing test for
// HandleSovereignToken's devicePattern guard, added by the same task that
// added the guard: the request never reaches the KV layer at all, so a
// hostile deviceId must be refused with 400 purely on pattern grounds.
func TestHandleSovereignToken_RejectsHostileDeviceId(t *testing.T) {
	for _, c := range hostileSovereignTokenDeviceIdCases {
		t.Run(c.name, func(t *testing.T) {
			dbpath = t.TempDir()
			kvStore := ID1KeyValueStore{}
			if _, _, err := GetOrCreateSigningKey(kvStore); err != nil {
				t.Fatal(err)
			}
			userID := "service"
			timestamp := time.Now().UTC().Format(time.RFC3339)
			body := `{"id":"` + userID + `","deviceId":"` + c.deviceId + `","timestamp":"` + timestamp + `","signature":"bm90LWEtcmVhbC1zaWc="}`
			req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/token", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			HandleSovereignToken(kvStore).ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("hostile deviceId %q must be refused with 400, got %d: %s", c.deviceId, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestRegistrationTokenPatternBoundaryLengths asserts registrationTokenPattern's
// stated 16-64 character bound at its edges: 15 and 65 characters must be
// rejected, 16 and 64 must be accepted. The pattern's alphabet character (a)
// is repeated to isolate length as the only variable under test.
func TestRegistrationTokenPatternBoundaryLengths(t *testing.T) {
	cases := []struct {
		name   string
		length int
		want   bool
	}{
		{name: "below floor (15)", length: 15, want: false},
		{name: "at floor (16)", length: 16, want: true},
		{name: "at ceiling (64)", length: 64, want: true},
		{name: "above ceiling (65)", length: 65, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok := strings.Repeat("a", c.length)
			got := registrationTokenPattern.MatchString(tok)
			if got != c.want {
				t.Errorf("registrationTokenPattern.MatchString(%d chars) = %v, want %v", c.length, got, c.want)
			}
		})
	}
}

// __END_OF_FILE_MARKER__
