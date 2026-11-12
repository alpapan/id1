// apps/id1/traefik_proof.go
//
// group: nextcloud
// tags: nextcloud, proxy, mtls, certificates
// summary: Proves a request on id1's listener came from Traefik's dedicated client certificate.
//
//

package id1

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// TraefikProxyClientCommonName is the commonName of the certificate Traefik presents
// to id1 on every route to id1's Nextcloud proxy (Certificate traefik-id1-proxy-client-cert,
// signed by the dedicated id1-proxy-mtls-ca).
const TraefikProxyClientCommonName = "traefik-id1-proxy-client"

// LoadCACertificate reads one PEM CA certificate from path.
func LoadCACertificate(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("id1: read CA certificate %s: %w", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("id1: %s holds no PEM certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("id1: parse CA certificate %s: %w", path, err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("id1: %s is not a CA certificate", path)
	}
	return cert, nil
}

// RequestFromTraefik reports whether the connection's verified client chain has leaf
// commonName TraefikProxyClientCommonName and ends at ca. The listener verifies the
// chain against its ClientCAs pool (which also holds the shared cluster CA), so the
// root is compared here: a certificate from the shared CA with the same commonName
// does not pass.
func RequestFromTraefik(state *tls.ConnectionState, ca *x509.Certificate) bool {
	if state == nil || ca == nil {
		return false
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) < 2 {
			continue
		}
		if chain[0].Subject.CommonName == TraefikProxyClientCommonName && chain[len(chain)-1].Equal(ca) {
			return true
		}
	}
	return false
}
