// apps/id1/nc_proxy_test.go
//
// group: nextcloud
// tags: nextcloud, proxy, client-address, mtls, testing
// summary: Tests for NewNextcloudProxyHandler and ResolveNextcloudProxyConfig.
//
//

package id1

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type seenRequest struct {
	path    string
	address []string
	edge    []string
}

type nextcloudStub struct {
	mu   sync.Mutex
	seen []seenRequest
}

func (s *nextcloudStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.seen = append(s.seen, seenRequest{path: r.URL.Path, address: r.Header.Values(ClientAddressHeader), edge: r.Header.Values(EdgeSecretHeader)})
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *nextcloudStub) requests() []seenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]seenRequest(nil), s.seen...)
}

func newProxyUnderTest(t *testing.T, rule ClientAddressRule, ca *x509.Certificate) (http.Handler, *nextcloudStub) {
	t.Helper()
	stub := &nextcloudStub{}
	backend := httptest.NewServer(stub)
	t.Cleanup(backend.Close)
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	return NewNextcloudProxyHandler(NextcloudProxyConfig{TargetURL: target, Rule: rule, TraefikCA: ca}), stub
}

// onComputePort returns req as if net/http had accepted it on ComputeProxyPort.
func onComputePort(req *http.Request) *http.Request {
	local := &net.TCPAddr{IP: net.ParseIP("10.42.0.5"), Port: 8081}
	return req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, local))
}

func TestNextcloudProxyHandlerStatesComputeAccountAddress(t *testing.T) {
	handler, stub := newProxyUnderTest(t, connectorTestRule(), nil)
	req := httptest.NewRequest("PROPFIND", "/nextcloud/remote.php/dav/files/0000-0002-1825-0097/", nil)
	req.SetBasicAuth("0000-0002-1825-0097", "app-password")
	// An unproved peer: on the main port the connector rule refuses it with 403.
	req.Header.Set("X-Real-Ip", "10.42.9.9")
	req.Header.Set(ClientAddressHeader, "198.51.100.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, onComputePort(req))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	seen := stub.requests()
	if len(seen) != 1 {
		t.Fatalf("Nextcloud saw %d requests, want 1", len(seen))
	}
	want := ComputeAccountAddress("0000-0002-1825-0097").String()
	if len(seen[0].address) != 1 || seen[0].address[0] != want {
		t.Fatalf("Nextcloud %s = %q, want exactly [%s]", ClientAddressHeader, seen[0].address, want)
	}
}

func TestNextcloudProxyHandlerRefusesComputeRequestWithoutAccount(t *testing.T) {
	handler, stub := newProxyUnderTest(t, connectorTestRule(), nil)
	req := httptest.NewRequest("PROPFIND", "/nextcloud/remote.php/dav/files/alice/", nil)
	req.SetBasicAuth("alice", "app-password")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, onComputePort(req))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if seen := stub.requests(); len(seen) != 0 {
		t.Fatalf("Nextcloud saw %d requests, want 0", len(seen))
	}
}

func TestNextcloudProxyHandlerStatesConnectorEdgeAddress(t *testing.T) {
	handler, stub := newProxyUnderTest(t, connectorTestRule(), nil)
	req := httptest.NewRequest("PROPFIND", "/nextcloud/remote.php/dav/files/u1/", nil)
	req.Header.Set("X-Real-Ip", "10.42.1.10")
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	req.Header.Set(ClientAddressHeader, "198.51.100.1")
	req.Header.Set("Connection", ClientAddressHeader)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	seen := stub.requests()
	if len(seen) != 1 {
		t.Fatalf("Nextcloud saw %d requests, want 1", len(seen))
	}
	if seen[0].path != "/remote.php/dav/files/u1/" {
		t.Fatalf("Nextcloud path = %q, want %q", seen[0].path, "/remote.php/dav/files/u1/")
	}
	if len(seen[0].address) != 1 || seen[0].address[0] != "203.0.113.7" {
		t.Fatalf("Nextcloud %s = %q, want exactly [203.0.113.7]", ClientAddressHeader, seen[0].address)
	}
}

func TestNextcloudProxyHandlerStripsBarePrefix(t *testing.T) {
	handler, stub := newProxyUnderTest(t, connectorTestRule(), nil)
	req := httptest.NewRequest(http.MethodGet, "/nextcloud", nil)
	req.Header.Set("X-Real-Ip", "127.0.0.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	seen := stub.requests()
	if len(seen) != 1 || seen[0].path != "/" {
		t.Fatalf("Nextcloud saw %+v, want one request for path /", seen)
	}
	if seen[0].address[0] != "127.0.0.1" {
		t.Fatalf("Nextcloud %s = %q, want [127.0.0.1]", ClientAddressHeader, seen[0].address)
	}
}

func TestNextcloudProxyHandlerRefusesUnprovedPeer(t *testing.T) {
	handler, stub := newProxyUnderTest(t, connectorTestRule(), nil)
	req := httptest.NewRequest(http.MethodGet, "/nextcloud/status.php", nil)
	req.Header.Set("X-Real-Ip", "10.42.9.9")
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if n := len(stub.requests()); n != 0 {
		t.Fatalf("Nextcloud saw %d requests, want 0", n)
	}
}

func TestNextcloudProxyHandlerRefusesPodRangeEdgeAddress(t *testing.T) {
	handler, stub := newProxyUnderTest(t, connectorTestRule(), nil)
	req := httptest.NewRequest(http.MethodGet, "/nextcloud/status.php", nil)
	req.Header.Set("X-Real-Ip", "10.42.1.10")
	req.Header.Set("CF-Connecting-IP", "10.42.5.5")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if n := len(stub.requests()); n != 0 {
		t.Fatalf("Nextcloud saw %d requests, want 0", n)
	}
}

func TestNextcloudProxyHandlerNeverForwardsEdgeSecret(t *testing.T) {
	handler, stub := newProxyUnderTest(t, secretTestRule(), nil)
	req := httptest.NewRequest(http.MethodGet, "/nextcloud/status.php", nil)
	req.Header.Set("X-Real-Ip", "10.42.9.9")
	req.Header.Set(EdgeSecretHeader, testEdgeSecret)
	req.Header.Set("CF-Connecting-IP", "2001:db8::7")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	seen := stub.requests()
	if len(seen) != 1 {
		t.Fatalf("Nextcloud saw %d requests, want 1 (status %d)", len(seen), rec.Code)
	}
	if len(seen[0].edge) != 0 {
		t.Fatalf("Nextcloud received %s = %q, want it removed", EdgeSecretHeader, seen[0].edge)
	}
	if seen[0].address[0] != "2001:db8::7" {
		t.Fatalf("Nextcloud %s = %q, want [2001:db8::7]", ClientAddressHeader, seen[0].address)
	}
}

func TestNextcloudProxyHandlerRequiresTraefikCertificateWhenCAConfigured(t *testing.T) {
	ca, caKey := newProofCA(t, "id1-proxy-mtls-ca")
	otherCA, otherKey := newProofCA(t, "curatorium-ca")
	traefikLeaf, _ := newProofLeaf(t, ca, caKey, TraefikProxyClientCommonName)
	backendLeaf, _ := newProofLeaf(t, otherCA, otherKey, "backend")
	handler, stub := newProxyUnderTest(t, connectorTestRule(), ca)

	noCert := httptest.NewRequest(http.MethodGet, "/nextcloud/status.php", nil)
	noCert.Header.Set("X-Real-Ip", "10.42.1.10")
	noCert.Header.Set("CF-Connecting-IP", "203.0.113.7")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, noCert)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no client certificate: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	sharedCA := httptest.NewRequest(http.MethodGet, "/nextcloud/status.php", nil)
	sharedCA.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{backendLeaf, otherCA}}}
	sharedCA.Header.Set("X-Real-Ip", "10.42.1.10")
	sharedCA.Header.Set("CF-Connecting-IP", "203.0.113.7")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, sharedCA)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("shared-CA certificate: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if n := len(stub.requests()); n != 0 {
		t.Fatalf("Nextcloud saw %d requests before a Traefik certificate, want 0", n)
	}

	fromTraefik := httptest.NewRequest(http.MethodGet, "/nextcloud/status.php", nil)
	fromTraefik.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{traefikLeaf, ca}}}
	fromTraefik.Header.Set("X-Real-Ip", "10.42.1.10")
	fromTraefik.Header.Set("CF-Connecting-IP", "203.0.113.7")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, fromTraefik)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("Traefik certificate: status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if n := len(stub.requests()); n != 1 {
		t.Fatalf("Nextcloud saw %d requests, want 1", n)
	}
}

type proxyEnvFiles struct {
	clientCert string
	clientKey  string
	serverCA   string
	traefikCA  string
}

func writeProxyEnvFiles(t *testing.T) proxyEnvFiles {
	t.Helper()
	dir := t.TempDir()
	clusterCA, _ := newProofCA(t, "curatorium-ca")
	clientCA, clientCAKey := newProofCA(t, "nextcloud-id1-mtls-ca")
	traefikCA, _ := newProofCA(t, "id1-proxy-mtls-ca")
	clientLeaf, clientKey := newProofLeaf(t, clientCA, clientCAKey, "id1-nextcloud-client")
	return proxyEnvFiles{
		clientCert: writeProofPEM(t, dir, "client.crt", "CERTIFICATE", clientLeaf.Raw),
		clientKey:  writeProofKey(t, dir, "client.key", clientKey),
		serverCA:   writeProofPEM(t, dir, "server-ca.crt", "CERTIFICATE", clusterCA.Raw),
		traefikCA:  writeProofPEM(t, dir, "traefik-ca.crt", "CERTIFICATE", traefikCA.Raw),
	}
}

func proxyEnv(files proxyEnvFiles, overrides map[string]string) func(string) string {
	env := map[string]string{
		"NEXTCLOUD_PROXY_URL":        "https://nextcloud:8087",
		"EDGE_PROOF_METHOD":          "connector-address",
		"CLUSTER_POD_CIDR":           "10.42.0.0/16",
		"MTLS_ENABLED":               "false",
		"NEXTCLOUD_CLIENT_CERT_FILE": files.clientCert,
		"NEXTCLOUD_CLIENT_KEY_FILE":  files.clientKey,
		"NEXTCLOUD_SERVER_CA_FILE":   files.serverCA,
		"TRAEFIK_PROXY_CA_FILE":      files.traefikCA,
	}
	for k, v := range overrides {
		env[k] = v
	}
	return func(key string) string { return env[key] }
}

func TestResolveNextcloudProxyConfigConnectorMethod(t *testing.T) {
	cfg, err := ResolveNextcloudProxyConfig(proxyEnv(writeProxyEnvFiles(t), nil))
	if err != nil {
		t.Fatalf("ResolveNextcloudProxyConfig: %v", err)
	}
	if cfg.TargetURL.String() != "https://nextcloud:8087" {
		t.Fatalf("TargetURL = %q", cfg.TargetURL.String())
	}
	if cfg.Rule.Method != EdgeProofConnectorAddress {
		t.Fatalf("Method = %q", cfg.Rule.Method)
	}
	if cfg.Rule.PodRange.String() != "10.42.0.0/16" {
		t.Fatalf("PodRange = %q", cfg.Rule.PodRange.String())
	}
	if cfg.Rule.Connectors == nil {
		t.Fatal("connector-address method must set Connectors")
	}
	if cfg.TraefikCA != nil {
		t.Fatal("TraefikCA must be nil when MTLS_ENABLED is not true")
	}
	if cfg.Transport == nil {
		t.Fatal("Transport must carry id1's Nextcloud client certificate")
	}
}

func TestResolveNextcloudProxyConfigEdgeSecretAndMTLS(t *testing.T) {
	cfg, err := ResolveNextcloudProxyConfig(proxyEnv(writeProxyEnvFiles(t), map[string]string{
		"EDGE_PROOF_METHOD": "edge-secret",
		"EDGE_PROOF_SECRET": testEdgeSecret,
		"MTLS_ENABLED":      "true",
	}))
	if err != nil {
		t.Fatalf("ResolveNextcloudProxyConfig: %v", err)
	}
	if cfg.Rule.EdgeSecret != testEdgeSecret {
		t.Fatal("EdgeSecret not taken from EDGE_PROOF_SECRET")
	}
	if cfg.TraefikCA == nil {
		t.Fatal("TraefikCA must be loaded when MTLS_ENABLED is true")
	}
}

func TestResolveNextcloudProxyConfigRefusals(t *testing.T) {
	cases := []struct {
		name      string
		overrides map[string]string
		wantKey   string
	}{
		{"proxy URL unset", map[string]string{"NEXTCLOUD_PROXY_URL": ""}, "NEXTCLOUD_PROXY_URL"},
		{"proxy URL not https", map[string]string{"NEXTCLOUD_PROXY_URL": "http://nextcloud:80"}, "NEXTCLOUD_PROXY_URL"},
		{"method unset", map[string]string{"EDGE_PROOF_METHOD": ""}, "EDGE_PROOF_METHOD"},
		{"method unknown", map[string]string{"EDGE_PROOF_METHOD": "auto"}, "EDGE_PROOF_METHOD"},
		{"pod range unset", map[string]string{"CLUSTER_POD_CIDR": ""}, "CLUSTER_POD_CIDR"},
		{"pod range not a prefix", map[string]string{"CLUSTER_POD_CIDR": "10.42.0.0"}, "CLUSTER_POD_CIDR"},
		{"edge secret unset", map[string]string{"EDGE_PROOF_METHOD": "edge-secret", "EDGE_PROOF_SECRET": ""}, "EDGE_PROOF_SECRET"},
		{"Traefik CA unset with mTLS on", map[string]string{"MTLS_ENABLED": "true", "TRAEFIK_PROXY_CA_FILE": ""}, "TRAEFIK_PROXY_CA_FILE"},
		{"client certificate unset", map[string]string{"NEXTCLOUD_CLIENT_CERT_FILE": ""}, "NEXTCLOUD_CLIENT_CERT_FILE"},
		{"server CA unset", map[string]string{"NEXTCLOUD_SERVER_CA_FILE": ""}, "NEXTCLOUD_SERVER_CA_FILE"},
	}
	files := writeProxyEnvFiles(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveNextcloudProxyConfig(proxyEnv(files, tc.overrides))
			if err == nil {
				t.Fatal("ResolveNextcloudProxyConfig accepted the configuration")
			}
			if !strings.Contains(err.Error(), tc.wantKey) {
				t.Fatalf("error %q does not name %s", err.Error(), tc.wantKey)
			}
		})
	}
}

func TestNoTraefikProofWarningNamesTheRisk(t *testing.T) {
	for _, want := range []string{"WARNING", "MTLS_ENABLED", "X-Real-Ip", "Nextcloud"} {
		if !strings.Contains(NoTraefikProofWarning, want) {
			t.Fatalf("NoTraefikProofWarning does not contain %q", want)
		}
	}
}
