package id1

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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
func newTestOrcidHandler(tokenServerURL, frontendURL string) *OrcidHandler {
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
	if !strings.Contains(location, "0000-0002-1825-0097") {
		t.Errorf("expected ORCID iD in redirect Location, got: %s", location)
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

	_, err := NewOrcidHandler()
	if err == nil {
		t.Fatal("expected error for missing ORCID_ISSUER_URL, got nil")
	}
	if !strings.Contains(err.Error(), "ORCID_ISSUER_URL") {
		t.Errorf("expected error about ORCID_ISSUER_URL, got: %v", err)
	}

	// Set issuer but keep others unset.
	os.Setenv("ORCID_ISSUER_URL", "https://orcid.org")
	_, err = NewOrcidHandler()
	if err == nil {
		t.Fatal("expected error for missing ORCID_CLIENT_ID, got nil")
	}
	if !strings.Contains(err.Error(), "ORCID_CLIENT_ID") {
		t.Errorf("expected error about ORCID_CLIENT_ID, got: %v", err)
	}

	// Set issuer and clientID but keep secret unset.
	os.Setenv("ORCID_CLIENT_ID", "test-id")
	_, err = NewOrcidHandler()
	if err == nil {
		t.Fatal("expected error for missing ORCID_CLIENT_SECRET, got nil")
	}
	if !strings.Contains(err.Error(), "ORCID_CLIENT_SECRET") {
		t.Errorf("expected error about ORCID_CLIENT_SECRET, got: %v", err)
	}
}

// __END_OF_FILE_MARKER__
