package id1

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMTLSConnectivity_SyncProxy tests that SyncProxy connects via mTLS
// when MTLS_ENABLED=true. The test creates a TLS server using the same
// certs that BuildTLSTransport will load, so the mTLS handshake succeeds.
func TestMTLSConnectivity_SyncProxy(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", certFile)
	t.Setenv("SSL_KEYFILE", keyFile)
	t.Setenv("SSL_CA_CERTS", caFile)

	// Create a TLS server using the same cert the proxy will trust.
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to load test cert: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("expected path '/', got: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("sync server ready"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	server.StartTLS()
	defer server.Close()

	// Extract host:port from the TLS server URL.
	target := strings.TrimPrefix(server.URL, "https://")

	handler, err := SyncProxy(target)
	if err != nil {
		t.Fatalf("SyncProxy failed to create handler: %v", err)
	}

	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL + "/sync")
	if err != nil {
		t.Fatalf("GET /sync failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d (OK), got %d (%s)",
			http.StatusOK, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
}

// TestMTLSConnectivity_SyncProxy_PlainHTTP tests that SyncProxy uses plain
// HTTP when MTLS_ENABLED is false.
func TestMTLSConnectivity_SyncProxy_PlainHTTP(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("sync server ready"))
	}))
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")

	handler, err := SyncProxy(target)
	if err != nil {
		t.Fatalf("SyncProxy failed to create handler: %v", err)
	}

	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL + "/sync")
	if err != nil {
		t.Fatalf("GET /sync failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d (OK), got %d (%s)",
			http.StatusOK, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
}

// TestMTLSConnectivity_NextcloudCreateUser tests that NextcloudProvisioner.createUser()
// correctly calls Nextcloud API when MTLS is enabled.
func TestMTLSConnectivity_NextcloudCreateUser(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", certFile)
	t.Setenv("SSL_KEYFILE", keyFile)
	t.Setenv("SSL_CA_CERTS", caFile)

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
// correctly calls Nextcloud API when MTLS is enabled.
func TestMTLSConnectivity_NextcloudCreateAppPassword(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", certFile)
	t.Setenv("SSL_KEYFILE", keyFile)
	t.Setenv("SSL_CA_CERTS", caFile)

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
