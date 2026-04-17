package id1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateRandomPassword verifies that the password generator produces
// non-empty passwords and handles errors gracefully.
func TestGenerateRandomPassword(t *testing.T) {
	// Test normal case - should produce non-empty password with NC_ prefix.
	password := generateRandomPassword()
	if password == "" {
		t.Error("generateRandomPassword returned empty string")
	}
	if !strings.HasPrefix(password, "NC_") {
		t.Errorf("expected password to have NC_ prefix, got: %s", password)
	}
	// Password should be long enough (base64 of 32 bytes).
	if len(password) < 40 {
		t.Errorf("expected password length >= 40, got %d", len(password))
	}

	// Test that subsequent calls produce different passwords.
	password2 := generateRandomPassword()
	if password == password2 {
		t.Error("expected different passwords on successive calls")
	}
}

// TestCreateUserRequest verifies that the create user request is built correctly
// with admin BasicAuth.
func TestCreateUserRequest(t *testing.T) {
	var capturedUser, capturedPass string
	var capturedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got: %s", r.Method)
		}
		if r.URL.Path != "/ocs/v2.php/cloud/users" {
			t.Errorf("expected /ocs/v2.php/cloud/users, got: %s", r.URL.Path)
		}
		if r.Header.Get("OCS-APIREQUEST") != "true" {
			t.Errorf("expected OCS-APIREQUEST: true header, got: %q", r.Header.Get("OCS-APIREQUEST"))
		}

		capturedUser, capturedPass, _ = r.BasicAuth()
		bodyBytes, _ := io.ReadAll(r.Body)
		capturedBody = string(bodyBytes)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OCSResponse{
			OCS: OCSData{
				Meta: OCSMeta{Statuscode: 100},
				Data: map[string]interface{}{"id": "test-user"},
			},
		})
	}))
	defer server.Close()

	// Set up provisioner with mock server URL.
	p := &NextcloudProvisioner{
		nextcloudURL: server.URL,
		username:     "admin",
		password:     "admin-secret",
	}

	err := p.createUser("test-user", "initial-password")
	if err != nil {
		t.Fatalf("createUser failed: %v", err)
	}

	if capturedUser != "admin" {
		t.Errorf("expected admin user for BasicAuth, got: %s", capturedUser)
	}
	if capturedPass != "admin-secret" {
		t.Errorf("expected admin-secret password, got: %s", capturedPass)
	}
	if !strings.Contains(capturedBody, "userid=test-user") {
		t.Errorf("expected form body to contain 'userid=test-user', got: %s", capturedBody)
	}
	if !strings.Contains(capturedBody, "password=initial-password") {
		t.Errorf("expected form body to contain 'password=initial-password', got: %s", capturedBody)
	}
}

// TestAppPasswordCall verifies that the app-password endpoint uses
// GET /ocs/v2.php/core/getapppassword with user BasicAuth and
// handles OCS statuscode 200 as success.
func TestAppPasswordCall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Error("expected BasicAuth for getapppassword")
		}

		// Verify it's the correct endpoint.
		if r.URL.Path != "/ocs/v2.php/core/getapppassword" {
			t.Errorf("expected /ocs/v2.php/core/getapppassword, got: %s", r.URL.Path)
		}

		// Verify it's GET.
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got: %s", r.Method)
		}
		if r.Header.Get("OCS-APIREQUEST") != "true" {
			t.Errorf("expected OCS-APIREQUEST: true header, got: %q", r.Header.Get("OCS-APIREQUEST"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OCSResponse{
			OCS: OCSData{
				Meta: OCSMeta{Statuscode: 200},
				Data: map[string]interface{}{
					"apppassword": "test-app-password-12345",
				},
			},
		})

		// Verify that user credentials (not admin credentials) are used for BasicAuth.
		if user != "test-orcid" {
			t.Errorf("expected BasicAuth user 'test-orcid', got: %s", user)
		}
		if pass != "user-password" {
			t.Errorf("expected BasicAuth password 'user-password', got: %s", pass)
		}
	}))
	defer server.Close()

	p := &NextcloudProvisioner{
		nextcloudURL: server.URL,
		username:     "admin",
		password:     "admin-secret",
	}

	appPassword, err := p.createAppPassword("test-orcid", "user-password")
	if err != nil {
		t.Fatalf("createAppPassword failed: %v", err)
	}

	if appPassword != "test-app-password-12345" {
		t.Errorf("expected app password, got: %s", appPassword)
	}
}

// TestCreateUserOCS102Idempotent verifies that OCS 102 (user already exists)
// is treated as success for idempotency.
func TestCreateUserOCS102Idempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OCSResponse{
			OCS: OCSData{
				Meta: OCSMeta{
					Statuscode: 102,
					Message:    "User already exists",
				},
			},
		})
	}))
	defer server.Close()

	p := &NextcloudProvisioner{
		nextcloudURL: server.URL,
		username:     "admin",
		password:     "admin-secret",
	}

	// Should not return an error for OCS 102.
	err := p.createUser("existing-user", "password")
	if err != nil {
		t.Errorf("expected no error for OCS 102 (user exists), got: %v", err)
	}
}

// TestScanAndProvisionIntegration tests that the provisioner correctly
// identifies and skips already-provisioned users.
func TestScanAndProvisionIntegration(t *testing.T) {
	// Create a temporary directory structure simulating the id1 key store.
	tmpDir := t.TempDir()

	// Save and restore the global dbpath.
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	// Create an ORCID directory structure:
	// tmpDir/
	//   0000-0001-0001-0001/
	//     pub/
	//       keys/
	//         default
	//   0000-0002-0002-0002/
	//     pub/
	//       keys/
	//         default
	//     priv/
	//       nc-token  <- already provisioned

	// User 1: unprovisioned (no nc-token).
	user1Dir := filepath.Join(tmpDir, "0000-0001-0001-0001", "pub", "keys")
	os.MkdirAll(user1Dir, 0755)
	os.WriteFile(filepath.Join(user1Dir, "default"), []byte("public-key-1"), 0644)

	// User 2: already provisioned.
	user2Dir := filepath.Join(tmpDir, "0000-0002-0002-0002", "pub", "keys")
	os.MkdirAll(user2Dir, 0755)
	os.WriteFile(filepath.Join(user2Dir, "default"), []byte("public-key-2"), 0644)
	tokenDir := filepath.Join(tmpDir, "0000-0002-0002-0002", "priv")
	os.MkdirAll(tokenDir, 0755)
	os.WriteFile(filepath.Join(tokenDir, "nc-token"), []byte("existing-token"), 0644)

	// Track HTTP requests.
	httpRequestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequestCount++
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/ocs/v2.php/cloud/users") {
			json.NewEncoder(w).Encode(OCSResponse{
				OCS: OCSData{
					Meta: OCSMeta{Statuscode: 100},
					Data: map[string]interface{}{"id": "user"},
				},
			})
		} else {
			json.NewEncoder(w).Encode(OCSResponse{
				OCS: OCSData{
					Meta: OCSMeta{Statuscode: 200},
					Data: map[string]interface{}{"apppassword": "token"},
				},
			})
		}
	}))
	defer server.Close()

	p := &NextcloudProvisioner{
		nextcloudURL: server.URL,
		username:     "admin",
		password:     "admin-secret",
		provisioned:  make(map[string]bool),
	}

	p.scanAndProvision()

	// Should provision user 1 with 2 HTTP requests (createUser + createAppPassword).
	// User 2 is skipped because nc-token already exists.
	if httpRequestCount != 2 {
		t.Errorf("expected 2 HTTP requests for 1 user provisioning, got: %d", httpRequestCount)
	}

	// Run again - should provision 0 users since user 1 is now marked as provisioned.
	httpRequestCount = 0
	p.scanAndProvision()
	if httpRequestCount != 0 {
		t.Errorf("expected 0 HTTP requests on second scan, got: %d", httpRequestCount)
	}

	// Verify user 2 (already provisioned) was never touched - no extra requests.
	p.scanAndProvision()
	if httpRequestCount != 0 {
		t.Errorf("expected 0 HTTP requests for already-provisioned user on third scan, got: %d", httpRequestCount)
	}
}

// TestProvisionUserFullFlow tests the complete provisioning flow including
// token persistence.
func TestProvisionUserFullFlow(t *testing.T) {
	tmpDir := t.TempDir()

	// Save and restore the global dbpath.
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	// Create user directory with pub/keys/default.
	userDir := filepath.Join(tmpDir, "0000-0003-0003-0003", "pub", "keys")
	os.MkdirAll(userDir, 0755)
	os.WriteFile(filepath.Join(userDir, "default"), []byte("public-key-3"), 0644)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/ocs/v2.php/cloud/users") {
			json.NewEncoder(w).Encode(OCSResponse{
				OCS: OCSData{
					Meta: OCSMeta{Statuscode: 100},
					Data: map[string]interface{}{"id": "user"},
				},
			})
		} else {
			json.NewEncoder(w).Encode(OCSResponse{
				OCS: OCSData{
					Meta: OCSMeta{Statuscode: 200},
					Data: map[string]interface{}{"apppassword": "generated-app-token-xyz"},
				},
			})
		}
	}))
	defer server.Close()

	p := &NextcloudProvisioner{
		nextcloudURL: server.URL,
		username:     "admin",
		password:     "admin-secret",
		provisioned:  make(map[string]bool),
	}

	p.scanAndProvision()

	// Verify nc-token was created.
	tokenPath := filepath.Join(tmpDir, "0000-0003-0003-0003", "priv", "nc-token")
	tokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("expected nc-token to be created, got error: %v", err)
	}

	if string(tokenData) != "generated-app-token-xyz" {
		t.Errorf("expected token 'generated-app-token-xyz', got: %s", string(tokenData))
	}
}

// TestCreateUserOCSError verifies that OCS error codes other than 100/102
// return an error.
func TestCreateUserOCSError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OCSResponse{
			OCS: OCSData{
				Meta: OCSMeta{
					Statuscode: 999,
					Message:    "Unknown error",
				},
			},
		})
	}))
	defer server.Close()

	p := &NextcloudProvisioner{
		nextcloudURL: server.URL,
		username:     "admin",
		password:     "admin-secret",
	}

	err := p.createUser("test-user", "password")
	if err == nil {
		t.Error("expected error for OCS 999, got nil")
	}
}

// TestCreateAppPasswordOCSError verifies that non-200 OCS responses return an error.
func TestCreateAppPasswordOCSError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OCSResponse{
			OCS: OCSData{
				Meta: OCSMeta{
					Statuscode: 997,
					Message:    "App password failed",
				},
			},
		})
	}))
	defer server.Close()

	p := &NextcloudProvisioner{
		nextcloudURL: server.URL,
		username:     "admin",
		password:     "admin-secret",
	}

	_, err := p.createAppPassword("test-user", "password")
	if err == nil {
		t.Error("expected error for OCS 997, got nil")
	}
}

// TestCreateAppPasswordMissingAppPassword verifies that a response missing
// the apppassword key returns an error.
func TestCreateAppPasswordMissingAppPassword(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OCSResponse{
			OCS: OCSData{
				Meta: OCSMeta{Statuscode: 200},
				Data: map[string]interface{}{},
			},
		})
	}))
	defer server.Close()

	p := &NextcloudProvisioner{
		nextcloudURL: server.URL,
		username:     "admin",
		password:     "admin-secret",
	}

	_, err := p.createAppPassword("test-user", "password")
	if err == nil {
		t.Error("expected error for missing apppassword key, got nil")
	}
}

// TestNewNextcloudProvisioner verifies that the constructor reads
// environment variables correctly.
func TestNewNextcloudProvisioner(t *testing.T) {
	// Set environment variables.
	os.Setenv("NEXTCLOUD_URL", "https://cloud.example.com")
	os.Setenv("NC_PROVISIONER_USER", "provisioner-user")
	os.Setenv("NC_PROVISIONER_PASSWORD", "provisioner-secret")
	defer func() {
		os.Unsetenv("NEXTCLOUD_URL")
		os.Unsetenv("NC_PROVISIONER_USER")
		os.Unsetenv("NC_PROVISIONER_PASSWORD")
	}()

	p := NewNextcloudProvisioner()

	if p.nextcloudURL != "https://cloud.example.com" {
		t.Errorf("expected nextcloudURL 'https://cloud.example.com', got: %s", p.nextcloudURL)
	}
	if p.username != "provisioner-user" {
		t.Errorf("expected username 'provisioner-user', got: %s", p.username)
	}
	if p.password != "provisioner-secret" {
		t.Errorf("expected password 'provisioner-secret', got: %s", p.password)
	}
}

// TestProvisionUserRetryUsesSamePassword verifies that when provisioning fails
// after createUser succeeds but createAppPassword fails, a retry uses the same
// staging password instead of generating a new one.
func TestProvisionUserRetryUsesSamePassword(t *testing.T) {
	origDbpath := dbpath
	tmpDir := t.TempDir()
	dbpath = tmpDir
	defer func() { dbpath = origDbpath }()

	orcidId := "0009-0002-8023-3658"
	keysDir := filepath.Join(tmpDir, orcidId, "pub", "keys")
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("failed to create keysDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "key1"), []byte("pk"), 0o644); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	var passwords []string
	callCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(r.URL.Path, "/cloud/users") {
			r.ParseForm()
			passwords = append(passwords, r.FormValue("password"))
			callCount++
			localCount := callCount

			if localCount == 1 {
				json.NewEncoder(w).Encode(OCSResponse{OCS: OCSData{Meta: OCSMeta{Statuscode: 100}}})
			} else {
				json.NewEncoder(w).Encode(OCSResponse{OCS: OCSData{Meta: OCSMeta{Statuscode: 102}}})
			}
			return
		}

		if strings.Contains(r.URL.Path, "/core/getapppassword") {
			localCount := callCount
			if localCount == 1 {
				json.NewEncoder(w).Encode(OCSResponse{OCS: OCSData{Meta: OCSMeta{Statuscode: 500, Message: "transient"}}})
			} else {
				json.NewEncoder(w).Encode(OCSResponse{OCS: OCSData{
					Meta: OCSMeta{Statuscode: 200},
					Data: map[string]interface{}{"apppassword": "app-token-xyz"},
				}})
			}
			return
		}
	}))
	defer server.Close()

	p := &NextcloudProvisioner{
		nextcloudURL: server.URL,
		username:     "admin",
		password:     "secret",
	}

	err := p.provisionUser(orcidId)
	if err == nil {
		t.Fatal("first attempt should fail (app password error)")
	}

	stagingKey := KK(orcidId, "priv", "nc-staging-password")
	stagingPath := filepath.Join(dbpath, stagingKey.String())
	if _, statErr := os.Stat(stagingPath); statErr != nil {
		t.Fatalf("staging password file should exist after failed attempt: %v", statErr)
	}

	err = p.provisionUser(orcidId)
	if err != nil {
		t.Fatalf("second attempt should succeed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(passwords) != 2 {
		t.Fatalf("expected 2 createUser calls, got %d", len(passwords))
	}
	if passwords[0] != passwords[1] {
		t.Errorf("retry must reuse the same password, got %q then %q", passwords[0], passwords[1])
	}

	if _, statErr := os.Stat(stagingPath); !os.IsNotExist(statErr) {
		t.Error("staging password should be deleted after successful provisioning")
	}
}

// TestScanAndProvisionRespectsBackoff verifies that when provisioning fails,
// the provisioner skips the user during the backoff period.
func TestScanAndProvisionRespectsBackoff(t *testing.T) {
	origDbpath := dbpath
	tmpDir := t.TempDir()
	dbpath = tmpDir
	defer func() { dbpath = origDbpath }()

	orcidId := "0001-0002-0003-0004"
	keysDir := filepath.Join(tmpDir, orcidId, "pub", "keys")
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("failed to create keysDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "key1"), []byte("pk"), 0o644); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	var mu sync.Mutex
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// Always fail with 429
		json.NewEncoder(w).Encode(OCSResponse{OCS: OCSData{Meta: OCSMeta{Statuscode: 429, Message: "Reached maximum delay"}}})
	}))
	defer server.Close()

	p := &NextcloudProvisioner{
		nextcloudURL: server.URL,
		username:     "admin",
		password:     "secret",
		provisioned:  make(map[string]bool),
		backoffUntil: make(map[string]time.Time),
		failCount:    make(map[string]int),
	}

	// First scan: attempts provisioning, fails, sets backoff
	p.scanAndProvision()
	mu.Lock()
	firstCount := requestCount
	mu.Unlock()
	if firstCount != 1 {
		t.Errorf("first scan should make 1 request, got %d", firstCount)
	}

	// Second scan immediately after: should skip due to backoff
	p.scanAndProvision()
	mu.Lock()
	secondCount := requestCount
	mu.Unlock()
	if secondCount != 1 {
		t.Errorf("second scan should skip user due to backoff, but made %d total requests", secondCount)
	}
}

// ---------------------------------------------------------------------------
// DeriveNextcloudPassword — HMAC-SHA256 based deterministic password derivation.
// ---------------------------------------------------------------------------

func TestDeriveNextcloudPassword_Deterministic(t *testing.T) {
	key := []byte("test-derivation-key")
	orcid := "0009-0002-8023-3658"
	pw1, err := DeriveNextcloudPassword(key, orcid)
	require.NoError(t, err)
	pw2, err := DeriveNextcloudPassword(key, orcid)
	require.NoError(t, err)
	assert.Equal(t, pw1, pw2, "same inputs must produce same output")
}

func TestDeriveNextcloudPassword_DifferentKeys(t *testing.T) {
	orcid := "0009-0002-8023-3658"
	pw1, err := DeriveNextcloudPassword([]byte("key1"), orcid)
	require.NoError(t, err)
	pw2, err := DeriveNextcloudPassword([]byte("key2"), orcid)
	require.NoError(t, err)
	assert.NotEqual(t, pw1, pw2, "different keys must produce different outputs")
}

func TestDeriveNextcloudPassword_DifferentOrcids(t *testing.T) {
	key := []byte("test-derivation-key")
	pw1, err := DeriveNextcloudPassword(key, "0009-0002-8023-3658")
	require.NoError(t, err)
	pw2, err := DeriveNextcloudPassword(key, "0000-0002-1825-0097")
	require.NoError(t, err)
	assert.NotEqual(t, pw1, pw2, "different orcids must produce different outputs")
}

func TestDeriveNextcloudPassword_NCPrefix(t *testing.T) {
	pw, err := DeriveNextcloudPassword([]byte("test-derivation-key"), "0009-0002-8023-3658")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(pw, "NC_"), "derived password must start with NC_ prefix")
}

func TestDeriveNextcloudPassword_EmptyKey(t *testing.T) {
	_, err := DeriveNextcloudPassword([]byte{}, "0009-0002-8023-3658")
	assert.Error(t, err, "empty derivation key must return error")
}

func TestDeriveNextcloudPassword_EmptyOrcid(t *testing.T) {
	_, err := DeriveNextcloudPassword([]byte("test-key"), "")
	assert.Error(t, err, "empty orcid must return error")
}

// ---------------------------------------------------------------------------
// NextcloudClient type — stateless HTTP client for Nextcloud OCS API.
// ---------------------------------------------------------------------------

func TestNewNextcloudClient_ReadsEnv(t *testing.T) {
	t.Setenv("NEXTCLOUD_URL", "http://test.example")
	t.Setenv("NC_PROVISIONER_USER", "admin")
	t.Setenv("NC_PROVISIONER_PASSWORD", "secret")

	c := NewNextcloudClient()

	assert.Equal(t, "http://test.example", c.URL)
	assert.Equal(t, "admin", c.Username)
	assert.Equal(t, "secret", c.Password)
}

func TestNewNextcloudClient_MissingEnvReturnsZeros(t *testing.T) {
	t.Setenv("NEXTCLOUD_URL", "")
	t.Setenv("NC_PROVISIONER_USER", "")
	t.Setenv("NC_PROVISIONER_PASSWORD", "")

	c := NewNextcloudClient()

	assert.Equal(t, "", c.URL)
	assert.Equal(t, "", c.Username)
	assert.Equal(t, "", c.Password)
}

// ---------------------------------------------------------------------------
// NextcloudClient.EnsureUserExists — idempotent OCS user-creation call.
// ---------------------------------------------------------------------------

func TestNextcloudClient_EnsureUserExists_Created(t *testing.T) {
	var gotPayload url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/ocs/v2.php/cloud/users", r.URL.Path)
		assert.Equal(t, "true", r.Header.Get("OCS-APIREQUEST"))
		body, _ := io.ReadAll(r.Body)
		gotPayload, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":100,"status":"ok","message":"OK"},"data":{}}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL, Username: "admin", Password: "secret"}
	err := c.EnsureUserExists(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	require.NoError(t, err)
	assert.Equal(t, "0009-0002-8023-3658", gotPayload.Get("userid"))
	assert.Equal(t, "NC_derivedPw", gotPayload.Get("password"))
}

func TestNextcloudClient_EnsureUserExists_AlreadyExists(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":102,"status":"failure","message":"User already exists"},"data":null}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL, Username: "admin", Password: "secret"}
	err := c.EnsureUserExists(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	assert.NoError(t, err, "102 (already exists) must be treated as success")
}

func TestNextcloudClient_EnsureUserExists_OCSError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":101,"status":"failure","message":"Invalid input"},"data":null}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL, Username: "admin", Password: "secret"}
	err := c.EnsureUserExists(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "OCS error 101")
}

// ---------------------------------------------------------------------------
// NextcloudClient.MintAppToken — OCS getapppassword call as the user.
// ---------------------------------------------------------------------------

func TestNextcloudClient_MintAppToken_Success(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/ocs/v2.php/core/getapppassword", r.URL.Path)
		assert.Equal(t, "true", r.Header.Get("OCS-APIREQUEST"))
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"PLAINTEXT-TOKEN-abc123"}}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL}
	token, err := c.MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	require.NoError(t, err)
	assert.Equal(t, "PLAINTEXT-TOKEN-abc123", token)
	assert.NotEmpty(t, gotAuth, "Basic Auth header must be set")
}

func TestNextcloudClient_MintAppToken_BadPassword(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL}
	_, err := c.MintAppToken(context.Background(), "0009-0002-8023-3658", "wrong")

	require.Error(t, err)
}

func TestNextcloudClient_MintAppToken_OCSNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":403,"status":"failure","message":"forbidden"},"data":null}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL}
	_, err := c.MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_pw")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "OCS error 403")
}

// ---------------------------------------------------------------------------
// HandleNcToken — HTTP handler for GET /internal/nc-token?orcid=<X>.
// ---------------------------------------------------------------------------

// fakeNextcloud starts an httptest.Server that handles the two OCS calls
// (EnsureUserExists + MintAppToken). Returns the URL and a cleanup func.
func fakeNextcloud(t *testing.T, _expectedPw, tokenToReturn string) (string, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ocs/v2.php/cloud/users":
			fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":100,"status":"ok","message":"OK"},"data":{}}}`)
		case "/ocs/v2.php/core/getapppassword":
			fmt.Fprintf(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"%s"}}}`, tokenToReturn)
		default:
			http.NotFound(w, r)
		}
	}))
	return srv.URL, srv.Close
}

func TestHandleNcToken_HappyPath(t *testing.T) {
	ncURL, cleanup := fakeNextcloud(t, "any", "MINTED-TOKEN")
	defer cleanup()

	handler := HandleNcToken(&NextcloudClient{URL: ncURL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret")

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "MINTED-TOKEN", body["token"])
}

func TestHandleNcToken_MissingOrcid(t *testing.T) {
	handler := HandleNcToken(&NextcloudClient{}, []byte("test-key"), "internal-secret")

	req := httptest.NewRequest("GET", "/internal/nc-token", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleNcToken_MalformedOrcid(t *testing.T) {
	handler := HandleNcToken(&NextcloudClient{}, []byte("test-key"), "internal-secret")

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=not-an-orcid", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleNcToken_MissingInternalSecret(t *testing.T) {
	handler := HandleNcToken(&NextcloudClient{}, []byte("test-key"), "internal-secret")

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	// no X-ID1-Internal-Secret header
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleNcToken_WrongInternalSecret(t *testing.T) {
	handler := HandleNcToken(&NextcloudClient{}, []byte("test-key"), "internal-secret")

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "wrong")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleNcToken_NextcloudDown(t *testing.T) {
	// Point at a closed server to force connection failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret")

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadGateway, rr.Code)
}

// __END_OF_FILE_MARKER__
