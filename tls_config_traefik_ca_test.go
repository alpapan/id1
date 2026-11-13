// apps/id1/tls_config_traefik_ca_test.go
//
// group: middleware
// tags: tls, mtls, certificates, testing
// summary: BuildTLSConfig adds the dedicated Traefik proxy CA to the client-CA pool.
//
//

package id1

import (
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
)

func setTLSTestEnv(t *testing.T, traefikCAFile string) {
	t.Helper()
	certFile, keyFile, caFile := generateTestCerts(t)
	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", certFile)
	t.Setenv("SSL_KEYFILE", keyFile)
	t.Setenv("SSL_CA_CERTS", caFile)
	t.Setenv("SSL_LE_CERTFILE", "")
	t.Setenv("SSL_LE_KEYFILE", "")
	t.Setenv("TRAEFIK_PROXY_CA_FILE", traefikCAFile)
}

func TestBuildTLSConfigTrustsTraefikProxyCA(t *testing.T) {
	traefikCA, traefikKey := newProofCA(t, "id1-proxy-mtls-ca")
	traefikLeaf, _ := newProofLeaf(t, traefikCA, traefikKey, TraefikProxyClientCommonName)
	setTLSTestEnv(t, writeProofPEM(t, t.TempDir(), "ca.crt", "CERTIFICATE", traefikCA.Raw))
	cfg, err := BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	opts := x509.VerifyOptions{Roots: cfg.ClientCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := traefikLeaf.Verify(opts); err != nil {
		t.Fatalf("Traefik's client certificate does not verify against the listener's ClientCAs: %v", err)
	}
}

func TestBuildTLSConfigWithoutTraefikProxyCADoesNotTrustIt(t *testing.T) {
	traefikCA, traefikKey := newProofCA(t, "id1-proxy-mtls-ca")
	traefikLeaf, _ := newProofLeaf(t, traefikCA, traefikKey, TraefikProxyClientCommonName)
	setTLSTestEnv(t, "")
	cfg, err := BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	opts := x509.VerifyOptions{Roots: cfg.ClientCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := traefikLeaf.Verify(opts); err == nil {
		t.Fatal("a certificate from a CA that TRAEFIK_PROXY_CA_FILE does not name verified against ClientCAs")
	}
}

func TestBuildTLSConfigRefusesUnreadableTraefikProxyCA(t *testing.T) {
	setTLSTestEnv(t, filepath.Join(t.TempDir(), "absent.crt"))
	if _, err := BuildTLSConfig(); err == nil || !strings.Contains(err.Error(), "TRAEFIK_PROXY_CA_FILE") {
		t.Fatalf("BuildTLSConfig error = %v, want an error naming TRAEFIK_PROXY_CA_FILE", err)
	}
}
