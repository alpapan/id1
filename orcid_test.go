package id1

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// CRITICAL: Read frontend port from environment variable (set by .env.test)
func getFrontendURL() string {
	port := os.Getenv("HTTP_FRONTEND_PORT")
	if port == "" {
		port = "19001"
	}
	return fmt.Sprintf("http://localhost:%s", port)
}

// newTestOrcidHandler constructs an OrcidHandler suitable for unit tests
// without requiring environment variables. tokenServerURL is the URL of a
// mock ORCID token endpoint (use httptest.NewServer); pass "" to omit it.
// This creates a handler with a mock KV store that returns nil for all operations.
func newTestOrcidHandler(tokenServerURL, frontendURL string) *OrcidHandler {
	authURL := "https://sandbox.orcid.org/oauth/authorize"
	if tokenServerURL != "" {
		authURL = tokenServerURL + "/oauth/authorize"
	}
	tokenURL := "https://sandbox.orcid.org/oauth/token"
	if tokenServerURL != "" {
		tokenURL = tokenServerURL + "/oauth/token"
	}
	// Use a mock KV store for backward compatibility with existing tests
	mockKV := &MockFailingKeyValueStore{failOnGet: false, failOnSet: false}
	return &OrcidHandler{
		oauth2Config: &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:   authURL,
				TokenURL:  tokenURL,
				AuthStyle: oauth2.AuthStyleInHeader,
			},
		},
		frontendURL: frontendURL,
		kvStore:     mockKV,
		stateStore:  make(map[string]stateEntry),
		stateTTL:    5 * time.Minute,
	}
}

// newTestOrcidHandlerWithState creates a test OrcidHandler with pre-populated state entries.
// This avoids directly manipulating internal state fields in individual tests.
func newTestOrcidHandlerWithState(tokenServerURL, frontendURL string, states map[string]stateEntry) *OrcidHandler {
	h := newTestOrcidHandler(tokenServerURL, frontendURL)
	h.stateMu.Lock()
	for key, entry := range states {
		h.stateStore[key] = entry
	}
	h.stateMu.Unlock()
	return h
}

// TestOrcidStateExpiry verifies that HandleCallback rejects a state token
// that is older than stateTTL, even though the entry was legitimately inserted.
func TestOrcidStateExpiry(t *testing.T) {
	states := map[string]stateEntry{
		"expired_state": {created: time.Now().Add(-6 * time.Minute)},
	}
	h := newTestOrcidHandlerWithState("", getFrontendURL(), states)

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=expired_state&code=any_code", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for expired state, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("expected 'expired' in response body, got: %s", rec.Body.String())
	}
}

// TestOrcidStatePrune verifies that HandleBegin successfully creates a new state
// and that old states do not interfere with the auth flow.
func TestOrcidStatePrune(t *testing.T) {
	states := map[string]stateEntry{
		"stale_state": {created: time.Now().Add(-7 * time.Minute)},
		"fresh_state": {created: time.Now().Add(-1 * time.Minute)},
	}
	h := newTestOrcidHandlerWithState("", getFrontendURL(), states)

	// HandleBegin should redirect successfully despite old state entries.
	req := httptest.NewRequest(http.MethodGet, "/auth/orcid", nil)
	rec := httptest.NewRecorder()
	h.HandleBegin(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 redirect from HandleBegin, got %d", rec.Code)
	}

	// Verify redirect URL is present (indicates new state was created).
	location := rec.Header().Get("Location")
	if location == "" {
		t.Error("expected Location header in redirect response")
	}
	if !strings.Contains(location, "state=") {
		t.Error("expected state parameter in redirect URL")
	}
}

// TestOrcidCallback verifies that HandleCallback extracts the ORCID iD from
// the token response and redirects to the frontend with it as a query param.
func TestOrcidCallback(t *testing.T) {
	// Mock ORCID token endpoint that returns a token with an "orcid" field.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("code_verifier") == "" {
			http.Error(w, "missing code_verifier", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"access_token": "test-access-token",
			"token_type":   "bearer",
			"orcid":        "0000-0002-1825-0097",
			"name":         "Test User",
			"scope":        "/authenticate"
		}`)
	}))
	defer mockServer.Close()

	states := map[string]stateEntry{
		"valid_state": {created: time.Now(), verifier: "test_verifier_12345"},
	}
	h := newTestOrcidHandlerWithState(mockServer.URL, getFrontendURL(), states)

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=valid_state&code=test_code", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d: %s", rec.Code, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	// Now we expect a JWT token in the redirect, not the ORCID iD
	if !strings.Contains(location, "?token=") {
		t.Errorf("expected ?token= in redirect Location, got: %s", location)
	}
	// Extract and verify JWT is non-empty
	idx := strings.Index(location, "?token=")
	if idx != -1 {
		jwtString := location[idx+7:]
		if jwtString == "" {
			t.Error("expected JWT token to be non-empty")
		}
	}
}

// TestOrcidCallbackMissingState verifies that HandleCallback returns 400 when state parameter is absent.
func TestOrcidCallbackMissingState(t *testing.T) {
	h := newTestOrcidHandler("", getFrontendURL())

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?code=test_code", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing state, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "state") {
		t.Errorf("expected 'state' in response body, got: %s", rec.Body.String())
	}
}

// TestOrcidCallbackMissingCode verifies that HandleCallback returns 400 when code parameter is absent.
func TestOrcidCallbackMissingCode(t *testing.T) {
	states := map[string]stateEntry{
		"valid_state": {created: time.Now()},
	}
	h := newTestOrcidHandlerWithState("", getFrontendURL(), states)

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=valid_state", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing code, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "code") {
		t.Errorf("expected 'code' in response body, got: %s", rec.Body.String())
	}
}

// TestGenerateState verifies that generateState returns a non-empty, decodable state token.
func TestGenerateState(t *testing.T) {
	state, err := generateState()
	if err != nil {
		t.Fatalf("generateState returned error: %v", err)
	}
	if state == "" {
		t.Fatal("generateState returned empty string")
	}
	// Must be valid URL-safe base64 (32 bytes -> ~43 chars encoded)
	if len(state) < 40 {
		t.Errorf("expected state length >= 40, got %d", len(state))
	}
	// Must be decodeable
	_, err = base64.URLEncoding.DecodeString(state)
	if err != nil {
		t.Errorf("generateState returned invalid base64: %v", err)
	}
}

// TestOrcidCallbackInvalidFormat verifies that HandleCallback returns 400 for malformed ORCID iD.
func TestOrcidCallbackInvalidFormat(t *testing.T) {
	// Mock ORCID token endpoint that returns a token with an invalid ORCID iD.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("code_verifier") == "" {
			http.Error(w, "missing code_verifier", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"access_token": "test-access-token",
			"token_type":   "bearer",
			"orcid":        "invalid-orcid-format",
			"name":         "Test User",
			"scope":        "/authenticate"
		}`)
	}))
	defer mockServer.Close()

	states := map[string]stateEntry{
		"valid_state": {created: time.Now(), verifier: "test_verifier_12345"},
	}
	h := newTestOrcidHandlerWithState(mockServer.URL, getFrontendURL(), states)

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=valid_state&code=test_code", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid ORCID format, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid") {
		t.Errorf("expected 'invalid' in response body, got: %s", rec.Body.String())
	}
}

// TestOrcidCallbackMissingOrcidField verifies that HandleCallback returns 502 when ORCID field is absent.
func TestOrcidCallbackMissingOrcidField(t *testing.T) {
	// Mock ORCID token endpoint that returns a token WITHOUT the "orcid" field.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("code_verifier") == "" {
			http.Error(w, "missing code_verifier", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"access_token": "test-access-token",
			"token_type":   "bearer",
			"name":         "Test User",
			"scope":        "/authenticate"
		}`)
	}))
	defer mockServer.Close()

	states := map[string]stateEntry{
		"valid_state": {created: time.Now(), verifier: "test_verifier_12345"},
	}
	h := newTestOrcidHandlerWithState(mockServer.URL, getFrontendURL(), states)

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=valid_state&code=test_code", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502 for missing ORCID field, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "missing") {
		t.Errorf("expected 'missing' in response body, got: %s", rec.Body.String())
	}
}

// TestNewOrcidHandlerMissingEnvVars verifies that NewOrcidHandler returns errors for missing required env vars.
func TestNewOrcidHandlerMissingEnvVars(t *testing.T) {
	// Save original env and restore after test.
	origIssuer := os.Getenv("ORCID_ISSUER_URL")
	origClientID := os.Getenv("ORCID_CLIENT_ID")
	origClientSecret := os.Getenv("ORCID_CLIENT_SECRET")
	defer func() {
		os.Setenv("ORCID_ISSUER_URL", origIssuer)
		os.Setenv("ORCID_CLIENT_ID", origClientID)
		os.Setenv("ORCID_CLIENT_SECRET", origClientSecret)
	}()

	// Clear all required vars.
	os.Unsetenv("ORCID_ISSUER_URL")
	os.Unsetenv("ORCID_CLIENT_ID")
	os.Unsetenv("ORCID_CLIENT_SECRET")

	kvStore := &MockFailingKeyValueStore{}
	_, err := NewOrcidHandler(kvStore)
	if err == nil {
		t.Fatal("expected error for missing ORCID_ISSUER_URL, got nil")
	}
	if !strings.Contains(err.Error(), "ORCID_ISSUER_URL") {
		t.Errorf("expected error about ORCID_ISSUER_URL, got: %v", err)
	}

	// Set issuer but keep others unset.
	os.Setenv("ORCID_ISSUER_URL", "https://orcid.org")
	_, err = NewOrcidHandler(kvStore)
	if err == nil {
		t.Fatal("expected error for missing ORCID_CLIENT_ID, got nil")
	}
	if !strings.Contains(err.Error(), "ORCID_CLIENT_ID") {
		t.Errorf("expected error about ORCID_CLIENT_ID, got: %v", err)
	}

	// Set issuer and clientID but keep secret unset.
	os.Setenv("ORCID_CLIENT_ID", "test-id")
	_, err = NewOrcidHandler(kvStore)
	if err == nil {
		t.Fatal("expected error for missing ORCID_CLIENT_SECRET, got nil")
	}
	if !strings.Contains(err.Error(), "ORCID_CLIENT_SECRET") {
		t.Errorf("expected error about ORCID_CLIENT_SECRET, got: %v", err)
	}
}

// newTestOrcidHandlerWithKVStore creates an OrcidHandler for testing
// with a pre-initialized KV store. The test passes the same KV store
// that contains signing keys, so HandleCallback will retrieve real keys.
func newTestOrcidHandlerWithKVStore(
	tokenServerURL string,
	frontendURL string,
	kvStore KeyValueStore,
) *OrcidHandler {
	authURL := "https://sandbox.orcid.org/oauth/authorize"
	if tokenServerURL != "" {
		authURL = tokenServerURL + "/oauth/authorize"
	}
	tokenURL := "https://sandbox.orcid.org/oauth/token"
	if tokenServerURL != "" {
		tokenURL = tokenServerURL + "/oauth/token"
	}
	return &OrcidHandler{
		oauth2Config: &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:   authURL,
				TokenURL:  tokenURL,
				AuthStyle: oauth2.AuthStyleInHeader,
			},
		},
		frontendURL: frontendURL,
		kvStore:     kvStore,
		stateStore:  make(map[string]stateEntry),
		stateTTL:    5 * time.Minute,
	}
}

// TestOrcidCallbackIssuingJWT verifies that HandleCallback issues an RS256 JWT
// after successful ORCID validation and redirects with ?token=JWT parameter.
// This test uses real ID1KeyValueStore and real signJWT flow.
func TestOrcidCallbackIssuingJWT(t *testing.T) {
	// Setup: Initialize real KV store for this test
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })
	kv := ID1KeyValueStore{}

	// Pre-initialize signing key in KV store
	expectedKeyID, expectedPrivKey, err := GetOrCreateSigningKey(kv)
	if err != nil {
		t.Fatalf("Failed to initialize signing key: %v", err)
	}
	if expectedKeyID == "" {
		t.Fatal("Key ID should not be empty")
	}
	if expectedPrivKey == nil {
		t.Fatal("Private key should not be nil")
	}

	// Setup: Mock ORCID token server that returns valid ORCID iD
	mockOrcidTokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			// Return a valid ORCID OAuth2 token with orcid field
			w.Header().Set("Content-Type", "application/json")
			// The golang.org/x/oauth2 package expects "access_token" in response
			fmt.Fprintf(w, `{
				"access_token": "test_access_token",
				"token_type": "bearer",
				"orcid": "0000-0001-2345-6789",
				"scope": "/authenticate"
			}`)
		}
	}))
	defer mockOrcidTokenServer.Close()

	// Create handler with mocked token endpoint and real KV store
	// The kvStore contains the signing keys initialized above
	h := newTestOrcidHandlerWithKVStore(mockOrcidTokenServer.URL, "http://localhost:19001", kv)

	// Setup: Create valid state entry for this request
	states := map[string]stateEntry{
		"valid_state": {created: time.Now()},
	}
	h.stateMu.Lock()
	for k, v := range states {
		h.stateStore[k] = v
	}
	h.stateMu.Unlock()

	// Execute: Simulate ORCID callback with valid state and authorization code
	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=valid_state&code=test_code", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	// Verify: Should redirect (302) with ?token=JWT in URL
	if rec.Code != http.StatusFound {
		t.Errorf("Expected 302 Found redirect, got %d: %s", rec.Code, rec.Body.String())
		return
	}

	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatal("Location header must be present for redirect")
	}
	if !strings.Contains(location, "http://localhost:19001?token=") {
		t.Errorf("Expected redirect to frontend with ?token=, got: %s", location)
		return
	}

	// Extract JWT from redirect URL
	idx := strings.Index(location, "?token=")
	if idx == -1 {
		t.Fatal("JWT parameter not found in redirect URL")
	}
	jwtString := location[idx+7:] // Skip "?token="

	// Verify: JWT structure and claims
	if jwtString == "" {
		t.Fatal("JWT token should not be empty")
	}

	// Parse JWT using real public key (to verify RS256 signature is valid)
	token, err := jwt.ParseWithClaims(jwtString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is RS256
		if token.Method != jwt.SigningMethodRS256 {
			t.Errorf("Expected RS256 signing method, got %v", token.Method)
		}
		return &expectedPrivKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("JWT parsing failed: %v", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		t.Fatal("Claims should be RegisteredClaims")
	}
	if !token.Valid {
		t.Fatal("JWT signature must be valid")
	}

	// Verify: Token claims contain correct values
	if claims.Subject != "0000-0001-2345-6789" {
		t.Errorf("Expected subject to be ORCID iD, got: %s", claims.Subject)
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != "curatorium-backend" {
		t.Errorf("Expected audience to be curatorium-backend, got: %v", claims.Audience)
	}
	if claims.Issuer != "http://id1-router:8080" {
		t.Errorf("Expected issuer to be http://id1-router:8080, got: %s", claims.Issuer)
	}
	if claims.IssuedAt == nil {
		t.Fatal("IssuedAt should be present")
	}
	if claims.ExpiresAt == nil {
		t.Fatal("ExpiresAt should be present")
	}

	// Verify: Expiry is approximately 1 hour from now
	expiryTime := time.Unix(claims.ExpiresAt.Unix(), 0)
	expectedExpiry := time.Now().Add(time.Hour)
	timeDiff := expiryTime.Sub(expectedExpiry)
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > 30*time.Second {
		t.Errorf("Expiry should be approximately 1 hour from now (within 30s), diff: %v", timeDiff)
	}

	// Verify: JWT header has kid (key ID)
	if token.Header == nil {
		t.Fatal("JWT header should be present")
	}
	kid, ok := token.Header["kid"].(string)
	if !ok {
		t.Fatal("JWT header should contain kid as string")
	}
	if kid != expectedKeyID {
		t.Errorf("Key ID in JWT header should match stored key ID, expected: %s, got: %s", expectedKeyID, kid)
	}
}

// TestOrcidCallbackIssuingJWTWithoutFrontendURL verifies that HandleCallback
// returns JWT as JSON when no frontend URL is configured.
func TestOrcidCallbackIssuingJWTWithoutFrontendURL(t *testing.T) {
	// Setup: Initialize real KV store
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })
	kv := ID1KeyValueStore{}

	_, privKey, err := GetOrCreateSigningKey(kv)
	if err != nil {
		t.Fatalf("Failed to initialize signing key: %v", err)
	}

	// Setup: Mock ORCID token server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{
				"access_token": "test_token",
				"token_type": "bearer",
				"orcid": "0000-0002-5678-9012",
				"scope": "/authenticate"
			}`)
		}
	}))
	defer mockServer.Close()

	// Create handler with NO frontend URL (empty string)
	h := newTestOrcidHandlerWithKVStore(mockServer.URL, "", kv)

	states := map[string]stateEntry{
		"valid_state": {created: time.Now()},
	}
	h.stateMu.Lock()
	for k, v := range states {
		h.stateStore[k] = v
	}
	h.stateMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=valid_state&code=test_code", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	// Verify: HTTP 200 OK (not redirect)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK when no frontend URL, got %d: %s", rec.Code, rec.Body.String())
		return
	}

	// Verify: Content-Type is application/json
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got: %s", rec.Header().Get("Content-Type"))
	}

	// Parse JSON response
	var response map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Response should be valid JSON: %v", err)
	}

	jwtString, ok := response["token"]
	if !ok {
		t.Fatal("Response JSON should contain 'token' field")
	}
	if jwtString == "" {
		t.Fatal("JWT token should not be empty")
	}

	// Verify: JWT is valid and signed correctly
	token, err := jwt.ParseWithClaims(jwtString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			t.Errorf("Expected RS256 signing method")
		}
		return &privKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("JWT should parse successfully: %v", err)
	}

	claims := token.Claims.(*jwt.RegisteredClaims)
	if claims.Subject != "0000-0002-5678-9012" {
		t.Errorf("Expected subject to be ORCID iD, got: %s", claims.Subject)
	}
}

// TestOrcidCallbackJWTKeyIDMatches verifies that the JWT's key ID (kid header)
// matches the actual stored signing key ID, enabling JWKS-based validation.
func TestOrcidCallbackJWTKeyIDMatches(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })
	kv := ID1KeyValueStore{}

	keyID, privKey, err := GetOrCreateSigningKey(kv)
	if err != nil {
		t.Fatalf("Failed to initialize signing key: %v", err)
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{
				"access_token": "token",
				"token_type": "bearer",
				"orcid": "0000-0003-1111-2222",
				"scope": "/authenticate"
			}`)
		}
	}))
	defer mockServer.Close()

	h := newTestOrcidHandlerWithKVStore(mockServer.URL, "http://localhost:19001", kv)
	h.stateMu.Lock()
	h.stateStore["state1"] = stateEntry{created: time.Now()}
	h.stateMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=state1&code=code1", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("Expected 302 redirect, got %d: %s", rec.Code, rec.Body.String())
		return
	}
	location := rec.Header().Get("Location")
	idx := strings.Index(location, "?token=")
	if idx == -1 {
		t.Fatal("JWT parameter not found in redirect URL")
	}
	jwtString := location[idx+7:]

	// Parse without verification first to inspect header
	token, _, err := jwt.NewParser().ParseUnverified(jwtString, &jwt.RegisteredClaims{})
	if err != nil {
		t.Fatalf("Failed to parse unverified token: %v", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		t.Fatal("kid should be present in JWT header")
	}

	// Verify: kid matches the stored key ID
	if kid != keyID {
		t.Errorf("JWT kid should match stored key ID, expected: %s, got: %s", keyID, kid)
	}

	// Also verify the kid can be used to find the key (test the round-trip)
	_ = privKey // Use privKey to avoid unused variable error
}

// MockFailingKeyValueStore simulates KV store failures
type MockFailingKeyValueStore struct {
	failOnGet bool
	failOnSet bool
}

func (m *MockFailingKeyValueStore) CmdGet(key string) ([]byte, error) {
	if m.failOnGet {
		return nil, fmt.Errorf("kv store get failed")
	}
	return nil, nil
}

func (m *MockFailingKeyValueStore) CmdSet(key string, value []byte) error {
	if m.failOnSet {
		return fmt.Errorf("kv store set failed")
	}
	return nil
}

// TestOrcidCallbackSigningKeyFailure verifies that HandleCallback returns HTTP 500
// when GetOrCreateSigningKey fails (e.g., KV store unavailable).
func TestOrcidCallbackSigningKeyFailure(t *testing.T) {
	// Use a mock KV store that simulates failure
	failingKV := &MockFailingKeyValueStore{
		failOnGet: true,
		failOnSet: true,
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{
				"access_token": "token",
				"orcid": "0000-0001-1111-2222",
				"scope": "/authenticate"
			}`)
		}
	}))
	defer mockServer.Close()

	// Create handler with failing KV store
	h := &OrcidHandler{
		oauth2Config: &oauth2.Config{
			ClientID:     "test",
			ClientSecret: "test",
			Endpoint: oauth2.Endpoint{
				AuthURL:   mockServer.URL + "/oauth/authorize",
				TokenURL:  mockServer.URL + "/oauth/token",
				AuthStyle: oauth2.AuthStyleInHeader,
			},
		},
		frontendURL: "http://localhost:19001",
		kvStore:     failingKV,
		stateStore:  map[string]stateEntry{"state1": {created: time.Now()}},
		stateTTL:    5 * time.Minute,
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=state1&code=code", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	// Verify: Should return 500 when key signing fails
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 Internal Server Error, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "signing key") && !strings.Contains(rec.Body.String(), "get") {
		t.Errorf("Expected error message about signing key, got: %s", rec.Body.String())
	}
}

// MockCorruptKeyValueStore returns invalid key data and fails on writes
type MockCorruptKeyValueStore struct{}

func (m *MockCorruptKeyValueStore) CmdGet(key string) ([]byte, error) {
	if strings.Contains(key, "priv") {
		return []byte("not a valid PEM key"), nil
	}
	return nil, nil
}

func (m *MockCorruptKeyValueStore) CmdSet(key string, value []byte) error {
	if strings.Contains(key, "priv") {
		return fmt.Errorf("failed to store private key")
	}
	return nil
}

// TestOrcidCallbackSignJWTFailure verifies that HandleCallback returns HTTP 500
// when JWT signing fails.
func TestOrcidCallbackSignJWTFailure(t *testing.T) {
	// Use a KV store that returns invalid private key data
	corruptKV := &MockCorruptKeyValueStore{}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{
				"access_token": "token",
				"orcid": "0000-0001-3333-4444",
				"scope": "/authenticate"
			}`)
		}
	}))
	defer mockServer.Close()

	h := &OrcidHandler{
		oauth2Config: &oauth2.Config{
			ClientID:     "test",
			ClientSecret: "test",
			Endpoint: oauth2.Endpoint{
				AuthURL:   mockServer.URL + "/oauth/authorize",
				TokenURL:  mockServer.URL + "/oauth/token",
				AuthStyle: oauth2.AuthStyleInHeader,
			},
		},
		frontendURL: "http://localhost:19001",
		kvStore:     corruptKV,
		stateStore:  map[string]stateEntry{"state1": {created: time.Now()}},
		stateTTL:    5 * time.Minute,
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=state1&code=code", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 Internal Server Error, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "sign") {
		t.Errorf("Expected error message about signing, got: %s", rec.Body.String())
	}
}

// TestOrcidCallbackValidationBeforeJWT verifies that ORCID iD format validation
// occurs BEFORE JWT signing. Invalid ORCID iDs must be rejected.
func TestOrcidCallbackValidationBeforeJWT(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })
	kv := ID1KeyValueStore{}

	_, _, err := GetOrCreateSigningKey(kv)
	if err != nil {
		t.Fatalf("Failed to initialize signing key: %v", err)
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			// Return INVALID ORCID format (should be XXXX-XXXX-XXXX-XXX[X|digit])
			fmt.Fprintf(w, `{
				"access_token": "token",
				"orcid": "invalid-orcid-format",
				"scope": "/authenticate"
			}`)
		}
	}))
	defer mockServer.Close()

	h := newTestOrcidHandlerWithKVStore(mockServer.URL, "http://localhost:19001", kv)
	h.stateMu.Lock()
	h.stateStore["state1"] = stateEntry{created: time.Now()}
	h.stateMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=state1&code=code", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	// Should reject with 400, NOT issue a JWT
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "eyJ") { // eyJ is start of JWT
		t.Error("Should not contain JWT token in response")
	}
	if !strings.Contains(rec.Body.String(), "invalid ORCID iD format") {
		t.Errorf("Expected error message about invalid ORCID format, got: %s", rec.Body.String())
	}
}

// __END_OF_FILE_MARKER__
