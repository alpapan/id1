package id1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMTLSConnectivity_SyncProxy tests that SyncProxy correctly routes to
// the sync server when MTLS is enabled. This test FAILS now (bug: tries https://)
// and PASSES after the fix (hardcode http://).
//
// The bug: SyncProxy calls BuildTLSTransport() when MTLS_ENABLED=true,
// which causes it to use scheme="https://" to reach the plain HTTP sync server,
// resulting in a 502 Bad Gateway error.
//
// The fix: Remove TLS logic from SyncProxy, hardcode http://.
func TestMTLSConnectivity_SyncProxy(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", certFile)
	t.Setenv("SSL_KEYFILE", keyFile)
	t.Setenv("SSL_CA_CERTS", caFile)

	// Start a plain HTTP test server (not HTTPS).
	// The sync server is plain HTTP only (no TLS).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("expected path '/', got: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("sync server ready"))
	}))
	defer server.Close()

	// Extract host:port from the test server URL.
	target := strings.TrimPrefix(server.URL, "http://")

	// Create the sync proxy.
	handler, err := SyncProxy(target)
	if err != nil {
		t.Fatalf("SyncProxy failed to create handler: %v", err)
	}

	// Simulate a GET /sync request.
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL + "/sync")
	if err != nil {
		t.Fatalf("GET /sync failed: %v", err)
	}
	defer resp.Body.Close()

	// EXPECTED (after fix): status == 200 (plain HTTP connection succeeds)
	// ACTUAL (before fix): status == 502 (tries https://, connection refused)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d (OK), got %d (%s). "+
			"This suggests SyncProxy is trying https:// to reach plain HTTP server. "+
			"Fix: hardcode http:// scheme in SyncProxy, remove TLS logic.",
			http.StatusOK, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
}

// TestMTLSConnectivity_NextcloudCreateUser tests that NextcloudProvisioner.createUser()
// correctly calls Nextcloud API when MTLS is enabled. This test PASSES now (no bug).
// It is a regression test to ensure Nextcloud connectivity is not broken by sync proxy fixes.
func TestMTLSConnectivity_NextcloudCreateUser(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", certFile)
	t.Setenv("SSL_KEYFILE", keyFile)
	t.Setenv("SSL_CA_CERTS", caFile)

	// Start a plain HTTP test server returning valid OCS response (statuscode 100).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got: %s", r.Method)
		}
		if r.URL.Path != "/ocs/v2.php/cloud/users" {
			t.Errorf("expected /ocs/v2.php/cloud/users, got: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OCSResponse{
			OCS: OCSData{
				Meta: OCSMeta{Statuscode: 100},
				Data: map[string]interface{}{"id": "test-user"},
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
	if err != nil {
		t.Fatalf("createUser failed: %v", err)
	}
}

// TestMTLSConnectivity_NextcloudCreateAppPassword tests that NextcloudProvisioner.createAppPassword()
// correctly calls Nextcloud API when MTLS is enabled. This test PASSES now (no bug).
// It is a regression test to ensure Nextcloud connectivity is not broken by sync proxy fixes.
func TestMTLSConnectivity_NextcloudCreateAppPassword(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", certFile)
	t.Setenv("SSL_KEYFILE", keyFile)
	t.Setenv("SSL_CA_CERTS", caFile)

	// Start a plain HTTP test server returning valid OCS response (statuscode 200).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got: %s", r.Method)
		}
		if r.URL.Path != "/ocs/v2.php/core/getapppassword" {
			t.Errorf("expected /ocs/v2.php/core/getapppassword, got: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OCSResponse{
			OCS: OCSData{
				Meta: OCSMeta{Statuscode: 200},
				Data: map[string]interface{}{"apppassword": "test-token-xyz"},
			},
		})
	}))
	defer server.Close()

	p := &NextcloudProvisioner{
		nextcloudURL: server.URL,
		username:     "admin",
		password:     "admin-secret",
	}

	token, err := p.createAppPassword("test-orcid", "user-pass")
	if err != nil {
		t.Fatalf("createAppPassword failed: %v", err)
	}

	if token != "test-token-xyz" {
		t.Errorf("expected token 'test-token-xyz', got: %s", token)
	}
}

// __END_OF_FILE_MARKER__
