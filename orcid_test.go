// apps/backend/containers/id1/orcid_test.go
//
// group: auth
// tags: orcid, oauth, testing
// summary: Tests for ORCID OAuth integration and token exchange.
//
//

package id1

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		panic("HTTP_FRONTEND_PORT env var not set - ensure .env.test is loaded before running Go tests")
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
		stateTTL:    5 * time.Minute,
	}
}

// seedState persists a CSRF state entry directly into the id1 KV store, mirroring
// what HandleBegin does. The caller MUST have pointed dbpath at a writable temp dir
// (e.g. via newTestOrcidHandlerWithState, or `dbpath = t.TempDir()`) first.
func seedState(t *testing.T, key string, entry stateEntry) {
	t.Helper()
	wire, err := json.Marshal(stateEntryWire{
		Created:     entry.created,
		Verifier:    entry.verifier,
		RedirectURI: entry.redirectURI,
	})
	if err != nil {
		t.Fatalf("failed to marshal seed state %q: %v", key, err)
	}
	if _, err := CmdSet(KK(stateKeyPrefix, key), map[string]string{"x-id": stateKeyPrefix}, wire).Exec(); err != nil {
		t.Fatalf("failed to seed state %q: %v", key, err)
	}
}

// readState reads a CSRF state entry back from the id1 KV store. ok is false when
// the key is absent (consumed, expired-and-swept, or never written).
func readState(t *testing.T, key string) (stateEntry, bool) {
	t.Helper()
	data, err := CmdGet(KK(stateKeyPrefix, key)).Exec()
	if err != nil || len(data) == 0 {
		return stateEntry{}, false
	}
	var wire stateEntryWire
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatalf("failed to unmarshal state %q: %v", key, err)
	}
	return stateEntry{created: wire.Created, verifier: wire.Verifier, redirectURI: wire.RedirectURI}, true
}

// stateFromRedirect extracts the `state` query parameter from a HandleBegin 302
// Location header (URL-decoding the value, which may carry base64 `=` padding).
func stateFromRedirect(t *testing.T, location string) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect Location %q: %v", location, err)
	}
	return u.Query().Get("state")
}

// newTestOrcidHandlerWithState creates a test OrcidHandler and seeds the given CSRF
// state entries into a fresh temp-dir KV store (dbpath). It takes *testing.T so it
// can point dbpath at t.TempDir() and restore it on cleanup.
func newTestOrcidHandlerWithState(t *testing.T, tokenServerURL, frontendURL string, states map[string]stateEntry) *OrcidHandler {
	t.Helper()
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
	h := newTestOrcidHandler(tokenServerURL, frontendURL)
	for key, entry := range states {
		seedState(t, key, entry)
	}
	return h
}

// TestOrcidStateExpiry verifies that HandleCallback rejects a state token
// that is older than stateTTL, even though the entry was legitimately inserted.
func TestOrcidStateExpiry(t *testing.T) {
	states := map[string]stateEntry{
		"expired_state": {created: time.Now().Add(-6 * time.Minute)},
	}
	h := newTestOrcidHandlerWithState(t, "", getFrontendURL(), states)

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
	h := newTestOrcidHandlerWithState(t, "", getFrontendURL(), states)

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

// TestOrcidStateSurvivesPodRestart verifies that a CSRF state created by one
// OrcidHandler instance can be validated by a DIFFERENT instance that shares the
// same id1 KV store (dbpath) - i.e. an in-flight ORCID login survives an id1 pod
// restart. The original in-memory-map implementation keeps state only in the
// per-instance map, so the second handler (fresh map) returns 400 "invalid
// state"; persisting state in the KV store makes the second handler complete the
// login with a 302 + token.
func TestOrcidStateSurvivesPodRestart(t *testing.T) {
	// Shared id1 KV store on a temp dbpath; it outlives a simulated pod restart.
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
	kv := ID1KeyValueStore{}
	if _, _, err := GetOrCreateSigningKey(kv); err != nil {
		t.Fatalf("failed to initialize signing key: %v", err)
	}

	// Mock ORCID token endpoint returning a valid token with an orcid field.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"access_token": "test-access-token",
			"token_type":   "bearer",
			"orcid":        "0000-0002-1825-0097",
			"scope":        "/authenticate"
		}`)
	}))
	defer mockServer.Close()

	// Handler A begins the flow and writes the CSRF state.
	handlerA := newTestOrcidHandlerWithKVStore(mockServer.URL, "http://localhost:19001", kv)
	beginRec := httptest.NewRecorder()
	handlerA.HandleBegin(beginRec, httptest.NewRequest(http.MethodGet, "/auth/orcid", nil))
	if beginRec.Code != http.StatusFound {
		t.Fatalf("HandleBegin: expected 302, got %d: %s", beginRec.Code, beginRec.Body.String())
	}
	loc, err := url.Parse(beginRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse HandleBegin redirect Location: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("HandleBegin redirect carried no state parameter")
	}

	// Simulated pod restart: a SEPARATE handler instance (fresh in-memory map),
	// same KV store. It must still recognise the in-flight state.
	handlerB := newTestOrcidHandlerWithKVStore(mockServer.URL, "http://localhost:19001", kv)
	cbReq := httptest.NewRequest(http.MethodGet,
		"/auth/orcid/callback?state="+url.QueryEscape(state)+"&code=test_code", nil)
	cbRec := httptest.NewRecorder()
	handlerB.HandleCallback(cbRec, cbReq)

	// Load-bearing: the post-restart handler must COMPLETE the login (302 + token),
	// not reject it with 400 "invalid state".
	if cbRec.Code != http.StatusFound {
		t.Fatalf("restart-survival: expected 302 from the post-restart handler, got %d: %s",
			cbRec.Code, cbRec.Body.String())
	}
	if !strings.Contains(cbRec.Header().Get("Location"), "token=") {
		t.Errorf("expected token= in redirect after restart, got: %s", cbRec.Header().Get("Location"))
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
	h := newTestOrcidHandlerWithState(t, mockServer.URL, getFrontendURL(), states)

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
	h := newTestOrcidHandlerWithState(t, "", getFrontendURL(), states)

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
	h := newTestOrcidHandlerWithState(t, mockServer.URL, getFrontendURL(), states)

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
	h := newTestOrcidHandlerWithState(t, mockServer.URL, getFrontendURL(), states)

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
	seedState(t, "valid_state", stateEntry{created: time.Now()})

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

	seedState(t, "valid_state", stateEntry{created: time.Now()})

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
	seedState(t, "state1", stateEntry{created: time.Now()})

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
// when GetOrCreateSigningKey fails. Under Shape B, the path-1 failure case is
// ID1_JWT_PRIVATE_KEY set without ID1_JWT_KEY_ID.
func TestOrcidCallbackSigningKeyFailure(t *testing.T) {
	// Reset memory cache so env var path is reached (not the cache).
	_memKeyMu.Lock()
	_memKeyID = ""
	_memPrivKey = nil
	_memKeyMu.Unlock()
	t.Cleanup(func() {
		_memKeyMu.Lock()
		_memKeyID = ""
		_memPrivKey = nil
		_memKeyMu.Unlock()
	})

	// Trigger path-1 error: private key env var set but key ID missing.
	t.Setenv("ID1_JWT_PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4T\n-----END RSA PRIVATE KEY-----\n")
	t.Setenv("ID1_JWT_KEY_ID", "") // empty → GetOrCreateSigningKey returns error

	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
	seedState(t, "state1", stateEntry{created: time.Now()})

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
		kvStore:     &MockFailingKeyValueStore{failOnGet: true, failOnSet: true},
		stateTTL:    5 * time.Minute,
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=state1&code=code", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

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
// when GetOrCreateSigningKey fails due to an invalid env-var private key PEM.
func TestOrcidCallbackSignJWTFailure(t *testing.T) {
	// Reset memory cache so env var path is reached.
	_memKeyMu.Lock()
	_memKeyID = ""
	_memPrivKey = nil
	_memKeyMu.Unlock()
	t.Cleanup(func() {
		_memKeyMu.Lock()
		_memKeyID = ""
		_memPrivKey = nil
		_memKeyMu.Unlock()
	})

	// Trigger path-1 parse error: env var set with invalid PEM.
	t.Setenv("ID1_JWT_PRIVATE_KEY", "not-a-valid-pem-block")
	t.Setenv("ID1_JWT_KEY_ID", "some-kid")

	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
	seedState(t, "state1", stateEntry{created: time.Now()})

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
		kvStore:     &MockCorruptKeyValueStore{},
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
	seedState(t, "state1", stateEntry{created: time.Now()})

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

// Test: HandleBegin stores redirect_uri from query param.
// Uses a test-only URI (no real port) since frontendURL validation is disabled (empty frontendURL).
func TestHandleBegin_StoresRedirectURI(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
	h := newTestOrcidHandler("", "")
	testRedirect := getFrontendURL() + "/auth/callback"

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid?redirect_uri="+testRedirect, nil)
	w := httptest.NewRecorder()
	h.HandleBegin(w, req)

	// Should redirect to ORCID
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	// Verify the persisted state entry stores redirect_uri.
	state := stateFromRedirect(t, w.Header().Get("Location"))
	entry, ok := readState(t, state)
	if !ok {
		t.Fatal("no state entry found in KV store")
	}
	if entry.redirectURI != testRedirect {
		t.Errorf("expected redirectURI %q, got %q", testRedirect, entry.redirectURI)
	}
}

// Test: HandleBegin uses frontendURL as fallback when no redirect_uri
func TestHandleBegin_FallbackToFrontendURL(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
	frontendURL := getFrontendURL()
	h := newTestOrcidHandler("", frontendURL)

	req := httptest.NewRequest(http.MethodGet, "/auth/orcid", nil)
	w := httptest.NewRecorder()
	h.HandleBegin(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	state := stateFromRedirect(t, w.Header().Get("Location"))
	entry, ok := readState(t, state)
	if !ok {
		t.Fatal("no state entry found in KV store")
	}
	if entry.redirectURI != frontendURL {
		t.Errorf("expected redirectURI %q, got %q", frontendURL, entry.redirectURI)
	}
}

// Test: HandleCallback redirects to stored redirect_uri with token
// Uses the same mock ORCID token server pattern as existing tests
// (e.g. TestHandleCallback_Success at orcid_test.go:414)
func TestHandleCallback_RedirectsToStoredRedirectURI(t *testing.T) {
	customRedirect := getFrontendURL() + "/auth/callback"
	// Use a distinct hostname for the "default" frontend so the test can distinguish
	// between redirecting to the stored URI vs falling back to the default.
	defaultFrontendURL := "http://other-frontend.internal"

	// Mock ORCID token endpoint that returns a valid token with ORCID iD
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"test-token","token_type":"bearer","orcid":"0000-0002-1825-0097"}`)
	}))
	defer tokenServer.Close()

	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
	h := newTestOrcidHandler(tokenServer.URL, defaultFrontendURL)

	// Pre-populate state with custom redirectURI
	state := "test-state-redirect"
	verifier := "test-verifier"
	seedState(t, state, stateEntry{
		created:     time.Now(),
		verifier:    verifier,
		redirectURI: customRedirect,
	})

	req := httptest.NewRequest(http.MethodGet,
		"/auth/orcid/callback?code=test-code&state="+state, nil)
	w := httptest.NewRecorder()
	h.HandleCallback(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, customRedirect+"?token=") {
		t.Errorf("expected redirect to %s?token=..., got %q", customRedirect, location)
	}
	// Must NOT redirect to the default frontendURL
	if strings.HasPrefix(location, defaultFrontendURL) {
		t.Errorf("should redirect to stored redirectURI, not default frontendURL")
	}
}

// Test: HandleBegin rejects redirect_uri that doesn't match allowed origins
func TestHandleBegin_RejectsExternalRedirectURI(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
	frontendURL := getFrontendURL()
	h := newTestOrcidHandler("", frontendURL)

	// Attempt open redirect to external domain
	req := httptest.NewRequest(http.MethodGet,
		"/auth/orcid?redirect_uri=https://evil.example.com/steal", nil)
	w := httptest.NewRecorder()
	h.HandleBegin(w, req)

	// HandleBegin sanitizes a mismatched redirect_uri to frontendURL and still 302s;
	// the evil URL must NEVER be the persisted redirectURI.
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 (fallback) for external redirect_uri, got %d", w.Code)
	}
	state := stateFromRedirect(t, w.Header().Get("Location"))
	entry, ok := readState(t, state)
	if !ok {
		t.Fatal("SECURITY: handler returned 302 but no state persisted - nothing to validate")
	}
	if entry.redirectURI == "https://evil.example.com/steal" {
		t.Error("SECURITY: external redirect_uri stored verbatim - open redirect vulnerability")
	}
	if entry.redirectURI != frontendURL && entry.redirectURI != "" {
		t.Errorf("SECURITY: expected fallback to %q or empty, got %q", frontendURL, entry.redirectURI)
	}
}

// Test: HandleBegin rejects subdomain-prefix bypass attacks
// A malicious actor might try to bypass origin validation by using a domain like
// https://app.example.com.evil.com when frontendURL is https://app.example.com.
// If the code naively uses strings.HasPrefix, this bypass works.
// This test ensures that proper URL parsing prevents this attack.
func TestHandleBegin_RejectsSubdomainPrefixBypass(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
	// Use a realistic frontend URL for production-like testing
	frontendURL := "https://app.example.com"
	h := newTestOrcidHandler("", frontendURL)

	// Attacker tries subdomain-prefix bypass: the hostname ends with the frontend domain
	// but is actually a different domain (attacker-controlled)
	attackerURL := "https://app.example.com.evil.com/steal"

	req := httptest.NewRequest(http.MethodGet,
		"/auth/orcid?redirect_uri="+url.QueryEscape(attackerURL), nil)
	w := httptest.NewRecorder()
	h.HandleBegin(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	// Verify the persisted redirectURI is NOT the attacker's URL.
	state := stateFromRedirect(t, w.Header().Get("Location"))
	entry, ok := readState(t, state)
	if !ok {
		t.Fatal("no state entry found in KV store")
	}
	if entry.redirectURI == attackerURL {
		t.Error("SECURITY: subdomain-prefix bypass succeeded - attacker URL was stored")
	}
	if entry.redirectURI != frontendURL {
		t.Errorf("SECURITY: expected fallback to %q, got %q", frontendURL, entry.redirectURI)
	}
}

// TestOrcidStateSingleUse verifies that a successful callback consumes the CSRF
// state: the KV key is deleted and a replay of the same state is rejected.
func TestOrcidStateSingleUse(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
	kv := ID1KeyValueStore{}
	if _, _, err := GetOrCreateSigningKey(kv); err != nil {
		t.Fatalf("failed to initialize signing key: %v", err)
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"t","token_type":"bearer","orcid":"0000-0002-1825-0097","scope":"/authenticate"}`)
	}))
	defer mockServer.Close()

	h := newTestOrcidHandlerWithKVStore(mockServer.URL, "http://localhost:19001", kv)
	seedState(t, "single_use_state", stateEntry{created: time.Now(), verifier: "v"})

	// First callback succeeds and must consume the state.
	req1 := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=single_use_state&code=c", nil)
	rec1 := httptest.NewRecorder()
	h.HandleCallback(rec1, req1)
	if rec1.Code != http.StatusFound {
		t.Fatalf("first callback: expected 302, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// The state key must be gone from the KV store.
	if _, ok := readState(t, "single_use_state"); ok {
		t.Error("state key still present after successful callback - not single-use")
	}

	// A replay with the same (now-consumed) state must be rejected.
	req2 := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=single_use_state&code=c", nil)
	rec2 := httptest.NewRecorder()
	h.HandleCallback(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("replay of consumed state: expected 400, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// TestOrcidStateGarbageCollectedByDotAfter verifies the TTL-scheduled delete is
// authorized (correct x-id) and that dotAfter sweeps an expired state off disk. A
// wrong x-id would leave the key undeleted, failing this test.
func TestOrcidStateGarbageCollectedByDotAfter(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	// Seed a state with a 1-second TTL via the same path HandleBegin uses.
	wire, err := json.Marshal(stateEntryWire{Created: time.Now(), Verifier: "v"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := CmdSet(KK(stateKeyPrefix, "gc_state"), map[string]string{"ttl": "1", "x-id": stateKeyPrefix}, wire).Exec(); err != nil {
		t.Fatalf("seed with ttl: %v", err)
	}
	if _, ok := readState(t, "gc_state"); !ok {
		t.Fatal("state should be present immediately after seeding")
	}

	// ttdMs = now + 1000 (cmd_set.go); dotAfter only fires once now > ttdMs.
	time.Sleep(1100 * time.Millisecond)
	dotAfter(dbpath)

	if _, ok := readState(t, "gc_state"); ok {
		t.Error("expired state was not garbage-collected by dotAfter (check x-id authorization)")
	}
}

// TestOrcidStateSetErrorReturns500 verifies HandleBegin returns 500 when the KV
// Set fails. State now uses package-level CmdSet (not the mockable kvStore), so a
// read-only dbpath is the way to exercise this error path.
func TestOrcidStateSetErrorReturns500(t *testing.T) {
	originalDbpath := dbpath
	roDir := t.TempDir()
	if err := os.Chmod(roDir, 0o500); err != nil {
		t.Skipf("cannot chmod temp dir read-only: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(roDir, 0o700) // restore so TempDir cleanup can remove it
		dbpath = originalDbpath
	})
	// Root bypasses 0500; skip if the dir is still writable.
	if f, err := os.CreateTemp(roDir, "probe"); err == nil {
		f.Close()
		t.Skip("dbpath is writable despite 0500 (likely running as root); cannot exercise Set failure")
	}
	dbpath = roDir

	h := newTestOrcidHandler("", "http://localhost:19001")
	req := httptest.NewRequest(http.MethodGet, "/auth/orcid", nil)
	w := httptest.NewRecorder()
	h.HandleBegin(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when KV Set fails, got %d: %s", w.Code, w.Body.String())
	}
}

// TestOrcidCallbackStateRejectsPathTraversal verifies that an attacker-controlled
// `state` containing path-traversal sequences cannot reach (and delete) a KV entry
// outside the _authstate namespace. The OAuth callback is public and unauthenticated;
// without strict validation, `..` in state escapes via filepath.Join in CmdGet/CmdDel.
func TestOrcidCallbackStateRejectsPathTraversal(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	// A victim KV entry outside the _authstate namespace (mirrors a device/signing key).
	if _, err := CmdSet(K("victimkey"), map[string]string{"x-id": "victimkey"}, []byte("secret")).Exec(); err != nil {
		t.Fatalf("seed victim: %v", err)
	}

	h := newTestOrcidHandler("", "http://localhost:19001")

	// `state` traverses from `_authstate/` up to `victimkey`.
	traversal := "../victimkey"
	req := httptest.NewRequest(http.MethodGet,
		"/auth/orcid/callback?state="+url.QueryEscape(traversal)+"&code=c", nil)
	rec := httptest.NewRecorder()
	h.HandleCallback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for traversal state, got %d: %s", rec.Code, rec.Body.String())
	}
	// Load-bearing: the victim must NOT have been deleted by the callback.
	if data, err := CmdGet(K("victimkey")).Exec(); err != nil || string(data) != "secret" {
		t.Errorf("SECURITY: path-traversal state deleted/altered a file outside the namespace (err=%v, data=%q)", err, string(data))
	}
}

// TestKVGetDelRejectDotDotSegments verifies that the KV get/del operations refuse a
// key containing a ".." segment, mirroring (and strengthening) the containment guard
// in move(). Defense-in-depth: a HasPrefix(dbpath) check alone would pass an in-root
// cross-namespace key like "a/../b", which still deletes another namespace's data.
func TestKVGetDelRejectDotDotSegments(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	// Victim INSIDE dbpath, in a different namespace (mirrors a device key).
	if _, err := CmdSet(K("victimns/secret"), map[string]string{"x-id": "victimns"}, []byte("secret")).Exec(); err != nil {
		t.Fatalf("seed victim: %v", err)
	}

	// A key that traverses cross-namespace via "..".
	escapeKey := K("_authstate/../victimns/secret")

	if _, err := CmdGet(escapeKey).Exec(); err == nil {
		t.Error("SECURITY: CmdGet accepted a key with a .. segment (cross-namespace traversal)")
	}
	if _, err := CmdDel(escapeKey).Exec(); err == nil {
		t.Error("SECURITY: CmdDel accepted a key with a .. segment (cross-namespace traversal)")
	}
	if data, err := CmdGet(K("victimns/secret")).Exec(); err != nil || string(data) != "secret" {
		t.Errorf("SECURITY: cross-namespace traversal deleted the victim (err=%v data=%q)", err, string(data))
	}
}

// __END_OF_FILE_MARKER__
