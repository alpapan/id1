package id1

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
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

// __END_OF_FILE_MARKER__
