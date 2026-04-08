package id1

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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
