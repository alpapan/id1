// apps/backend/containers/id1/tls_config_test.go
//
// group: middleware
// tags: tls, mtls, testing
// summary: Tests for TLS and mTLS configuration.
//
//

package id1

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestCerts(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()
	dir := t.TempDir()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:         true,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	caFile = filepath.Join(dir, "ca.crt")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	require.NoError(t, os.WriteFile(certFile, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0600))
	require.NoError(t, os.WriteFile(caFile, certPEM, 0600))

	return certFile, keyFile, caFile
}

func TestBuildTLSConfig_WhenEnabled(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", certFile)
	t.Setenv("SSL_KEYFILE", keyFile)
	t.Setenv("SSL_CA_CERTS", caFile)

	tlsConfig, err := BuildTLSConfig()
	assert.NoError(t, err)
	assert.NotNil(t, tlsConfig)
	assert.Equal(t, tls.VerifyClientCertIfGiven, tlsConfig.ClientAuth)
	assert.NotNil(t, tlsConfig.ClientCAs)
}

func TestBuildTLSConfig_WhenDisabled(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")

	tlsConfig, err := BuildTLSConfig()
	assert.NoError(t, err)
	assert.Nil(t, tlsConfig)
}

func TestBuildTLSConfig_NoCA_FailsClosed(t *testing.T) {
	certFile, keyFile, _ := generateTestCerts(t)
	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", certFile)
	t.Setenv("SSL_KEYFILE", keyFile)
	t.Setenv("SSL_CA_CERTS", "") // no client CA configured

	cfg, err := BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	// With no CA, ClientCAs must be a non-nil AND EMPTY pool so a presented client cert
	// cannot verify against the host SYSTEM root pool (which would fail OPEN to any
	// web-PKI cert). An empty pool fails the client-cert verification closed.
	require.NotNil(t, cfg.ClientCAs, "ClientCAs must be non-nil when MTLS_ENABLED even without SSL_CA_CERTS")
	require.True(t, cfg.ClientCAs.Equal(x509.NewCertPool()), "ClientCAs must be an EMPTY pool (no trust anchors) when SSL_CA_CERTS is unset")
}

func TestBuildTLSTransport_WhenEnabled(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", certFile)
	t.Setenv("SSL_KEYFILE", keyFile)
	t.Setenv("SSL_CA_CERTS", caFile)

	transport, err := BuildTLSTransport()
	assert.NoError(t, err)
	assert.NotNil(t, transport)
	assert.NotNil(t, transport.TLSClientConfig)
	assert.Len(t, transport.TLSClientConfig.Certificates, 1)
}

func TestBuildTLSTransport_WhenDisabled(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")
	transport, err := BuildTLSTransport()
	assert.NoError(t, err)
	assert.Nil(t, transport)
}

// generateTestCertWithSANs creates a self-signed RSA cert with specific SANs.
func generateTestCertWithSANs(t *testing.T, dir, prefix string, dnsNames []string) (certPath, keyPath string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: prefix},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:         true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPath = filepath.Join(dir, prefix+".crt")
	keyPath = filepath.Join(dir, prefix+".key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	return certPath, keyPath
}

func TestBuildTLSConfig_SNI_SelectsLECertForCuratoriumApp(t *testing.T) {
	dir := t.TempDir()

	cmCert, cmKey := generateTestCertWithSANs(t, dir, "cm", []string{"id1-router"})
	leCert, leKey := generateTestCertWithSANs(t, dir, "le", []string{"auth.curatorium.app", "demo.curatorium.app"})

	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", cmCert)
	t.Setenv("SSL_KEYFILE", cmKey)
	t.Setenv("SSL_CA_CERTS", cmCert)
	t.Setenv("SSL_LE_CERTFILE", leCert)
	t.Setenv("SSL_LE_KEYFILE", leKey)
	t.Setenv("CURATORIUM_DOMAIN", "curatorium.app")

	cfg, err := BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.GetCertificate, "GetCertificate must be set for SNI selection")

	hello := &tls.ClientHelloInfo{ServerName: "auth.curatorium.app"}
	cert, err := cfg.GetCertificate(hello)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, "le", leaf.Subject.CommonName)
}

func TestBuildTLSConfig_SNI_SelectsCMCertForInternal(t *testing.T) {
	dir := t.TempDir()

	cmCert, cmKey := generateTestCertWithSANs(t, dir, "cm", []string{"id1-router"})
	leCert, leKey := generateTestCertWithSANs(t, dir, "le", []string{"auth.curatorium.app"})

	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", cmCert)
	t.Setenv("SSL_KEYFILE", cmKey)
	t.Setenv("SSL_CA_CERTS", cmCert)
	t.Setenv("SSL_LE_CERTFILE", leCert)
	t.Setenv("SSL_LE_KEYFILE", leKey)
	t.Setenv("CURATORIUM_DOMAIN", "curatorium.app")

	cfg, err := BuildTLSConfig()
	require.NoError(t, err)

	hello := &tls.ClientHelloInfo{ServerName: "id1-router"}
	cert, err := cfg.GetCertificate(hello)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, "cm", leaf.Subject.CommonName)
}

func TestBuildTLSConfig_NoLECert_FallsBackToCM(t *testing.T) {
	dir := t.TempDir()

	cmCert, cmKey := generateTestCertWithSANs(t, dir, "cm", []string{"id1-router"})

	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", cmCert)
	t.Setenv("SSL_KEYFILE", cmKey)
	t.Setenv("SSL_CA_CERTS", cmCert)
	t.Setenv("CURATORIUM_DOMAIN", "curatorium.app")
	// No LE cert env vars

	cfg, err := BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	hello := &tls.ClientHelloInfo{ServerName: "auth.curatorium.app"}
	cert, err := cfg.GetCertificate(hello)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, "cm", leaf.Subject.CommonName, "without LE cert, all SNI should get CM cert")
}

func TestBuildTLSConfig_SNI_UsesConfiguredDomainSuffix(t *testing.T) {
	dir := t.TempDir()

	cmCert, cmKey := generateTestCertWithSANs(t, dir, "cm", []string{"id1-router"})
	leCert, leKey := generateTestCertWithSANs(t, dir, "le", []string{"auth.example-test.org"})

	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", cmCert)
	t.Setenv("SSL_KEYFILE", cmKey)
	t.Setenv("SSL_CA_CERTS", cmCert)
	t.Setenv("SSL_LE_CERTFILE", leCert)
	t.Setenv("SSL_LE_KEYFILE", leKey)
	t.Setenv("CURATORIUM_DOMAIN", "example-test.org")

	cfg, err := BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	hello := &tls.ClientHelloInfo{ServerName: "auth.example-test.org"}
	cert, err := cfg.GetCertificate(hello)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, "le", leaf.Subject.CommonName, "SNI suffix must be driven by CURATORIUM_DOMAIN, not hardcoded to curatorium.app")
}

// TestBuildTLSConfig_SNI_RejectsSuffixConfusion pins down that the configured-domain
// match is a real dot-delimited suffix match, not a bare substring match. A ServerName
// that merely contains the domain (as a label prefix, or without the separating dot)
// must NOT be treated as belonging to the domain - that would let an attacker-chosen
// name like "curatorium.app.evil.example" or "evilcuratorium.app" claim the public
// Let's Encrypt cert's trust context.
func TestBuildTLSConfig_SNI_RejectsSuffixConfusion(t *testing.T) {
	dir := t.TempDir()

	cmCert, cmKey := generateTestCertWithSANs(t, dir, "cm", []string{"id1-router"})
	leCert, leKey := generateTestCertWithSANs(t, dir, "le", []string{"auth.curatorium.app"})

	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", cmCert)
	t.Setenv("SSL_KEYFILE", cmKey)
	t.Setenv("SSL_CA_CERTS", cmCert)
	t.Setenv("SSL_LE_CERTFILE", leCert)
	t.Setenv("SSL_LE_KEYFILE", leKey)
	t.Setenv("CURATORIUM_DOMAIN", "curatorium.app")

	cfg, err := BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	cases := []struct {
		name       string
		serverName string
	}{
		{"domain-as-prefix-label", "curatorium.app.evil.example"},
		{"domain-suffix-without-separator", "evilcuratorium.app"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hello := &tls.ClientHelloInfo{ServerName: tc.serverName}
			cert, err := cfg.GetCertificate(hello)
			require.NoError(t, err)

			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			require.NoError(t, err)
			assert.Equal(t, "cm", leaf.Subject.CommonName,
				"ServerName %q must not be treated as under curatorium.app", tc.serverName)
		})
	}
}

// TestBuildTLSConfig_SNI_EmptyDomainRefusesToServe pins down that an unset/empty
// CURATORIUM_DOMAIN must NOT silently default to "curatorium.app" and must NOT
// silently compare against a bare empty-string suffix (which would only match
// ServerNames ending in a literal trailing dot - itself an unintended
// match-everything-ish degradation). With an LE cert configured but no domain to
// scope it, GetCertificate must refuse rather than guess for EVERY ServerName,
// including one that would have matched the old hardcoded default.
func TestBuildTLSConfig_SNI_EmptyDomainRefusesToServe(t *testing.T) {
	dir := t.TempDir()

	cmCert, cmKey := generateTestCertWithSANs(t, dir, "cm", []string{"id1-router"})
	leCert, leKey := generateTestCertWithSANs(t, dir, "le", []string{"auth.curatorium.app"})

	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("SSL_CERTFILE", cmCert)
	t.Setenv("SSL_KEYFILE", cmKey)
	t.Setenv("SSL_CA_CERTS", cmCert)
	t.Setenv("SSL_LE_CERTFILE", leCert)
	t.Setenv("SSL_LE_KEYFILE", leKey)
	t.Setenv("CURATORIUM_DOMAIN", "") // explicitly empty, same as unset from os.Getenv's view

	cfg, err := BuildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// A ServerName that would have matched the old hardcoded "curatorium.app"
	// default must now be refused, not silently served the LE cert.
	leHello := &tls.ClientHelloInfo{ServerName: "auth.curatorium.app"}
	_, err = cfg.GetCertificate(leHello)
	require.Error(t, err, "an unset CURATORIUM_DOMAIN with an LE cert configured must refuse rather than guess a default suffix")

	// An unrelated name must be refused too - proves this is a real refusal, not
	// an accidental match-everything suffix that happens to also reject one name.
	unrelatedHello := &tls.ClientHelloInfo{ServerName: "auth.evil.example"}
	_, err = cfg.GetCertificate(unrelatedHello)
	require.Error(t, err, "an unset CURATORIUM_DOMAIN with an LE cert configured must refuse for any ServerName")
}
