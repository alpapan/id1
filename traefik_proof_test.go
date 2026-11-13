// apps/id1/traefik_proof_test.go
//
// group: nextcloud
// tags: nextcloud, proxy, mtls, certificates, testing
// summary: Tests for LoadCACertificate and RequestFromTraefik.
//
//

package id1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newProofCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return cert, key
}

func newProofLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return cert, key
}

func writeProofPEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func writeProofKey(t *testing.T, dir, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return writeProofPEM(t, dir, name, "EC PRIVATE KEY", der)
}

func TestLoadCACertificateReadsPEM(t *testing.T) {
	ca, _ := newProofCA(t, "id1-proxy-mtls-ca")
	path := writeProofPEM(t, t.TempDir(), "ca.crt", "CERTIFICATE", ca.Raw)
	got, err := LoadCACertificate(path)
	if err != nil {
		t.Fatalf("LoadCACertificate: %v", err)
	}
	if !got.Equal(ca) {
		t.Fatal("loaded certificate differs from the one written")
	}
}

func TestLoadCACertificateRefusesNonPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadCACertificate(path); err == nil {
		t.Fatal("LoadCACertificate accepted a file with no PEM certificate")
	}
}

func TestLoadCACertificateRefusesLeaf(t *testing.T) {
	ca, caKey := newProofCA(t, "id1-proxy-mtls-ca")
	leaf, _ := newProofLeaf(t, ca, caKey, TraefikProxyClientCommonName)
	path := writeProofPEM(t, t.TempDir(), "ca.crt", "CERTIFICATE", leaf.Raw)
	if _, err := LoadCACertificate(path); err == nil {
		t.Fatal("LoadCACertificate accepted a certificate that is not a CA")
	}
}

func TestLoadCACertificateRefusesMissingFile(t *testing.T) {
	if _, err := LoadCACertificate(filepath.Join(t.TempDir(), "absent.crt")); err == nil {
		t.Fatal("LoadCACertificate accepted a missing file")
	}
}

func TestRequestFromTraefik(t *testing.T) {
	ca, caKey := newProofCA(t, "id1-proxy-mtls-ca")
	otherCA, otherKey := newProofCA(t, "curatorium-ca")
	traefikLeaf, _ := newProofLeaf(t, ca, caKey, TraefikProxyClientCommonName)
	wrongName, _ := newProofLeaf(t, ca, caKey, "backend")
	wrongCA, _ := newProofLeaf(t, otherCA, otherKey, TraefikProxyClientCommonName)
	cases := []struct {
		name  string
		state *tls.ConnectionState
		want  bool
	}{
		{"Traefik certificate from the dedicated CA", &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{traefikLeaf, ca}}}, true},
		{"other commonName from the dedicated CA", &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{wrongName, ca}}}, false},
		{"Traefik commonName from another CA", &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{wrongCA, otherCA}}}, false},
		{"no verified chain", &tls.ConnectionState{}, false},
		{"leaf only, no root", &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{traefikLeaf}}}, false},
		{"no TLS", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RequestFromTraefik(tc.state, ca); got != tc.want {
				t.Fatalf("RequestFromTraefik = %v, want %v", got, tc.want)
			}
		})
	}
	if RequestFromTraefik(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{traefikLeaf, ca}}}, nil) {
		t.Fatal("RequestFromTraefik with no CA configured must be false")
	}
}
