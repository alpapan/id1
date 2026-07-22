// apps/backend/containers/id1/tls_config.go
//
// group: middleware
// tags: tls, mtls, certificates, encryption
// summary: TLS/mTLS configuration for HTTPS and mutual authentication.
// Supports SNI-based certificate selection and client certificate validation.
//
//

package id1

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// BuildTLSConfig builds a *tls.Config when MTLS_ENABLED=true.
// Returns nil when mTLS is disabled (plain HTTP).
//
// Supports SNI-based certificate selection:
//   - SSL_CERTFILE / SSL_KEYFILE: primary cert (cert-manager, for internal traffic)
//   - SSL_LE_CERTFILE / SSL_LE_KEYFILE: optional Let's Encrypt cert (for *.CURATORIUM_DOMAIN)
//
// When both certs are available, GetCertificate selects the LE cert for
// SNI names under CURATORIUM_DOMAIN and the cert-manager cert for everything
// else. CURATORIUM_DOMAIN has no default: if it is unset or empty while an LE
// cert is configured, GetCertificate refuses (returns an error) rather than
// guessing a default suffix or matching every SNI name.
func BuildTLSConfig() (*tls.Config, error) {
	if os.Getenv("MTLS_ENABLED") != "true" {
		return nil, nil
	}

	certFile := os.Getenv("SSL_CERTFILE")
	keyFile := os.Getenv("SSL_KEYFILE")
	caFile := os.Getenv("SSL_CA_CERTS")

	defaultCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("id1: failed to load TLS cert/key: %w", err)
	}

	// Try loading the optional LE cert.
	var leCert *tls.Certificate
	leCertFile := os.Getenv("SSL_LE_CERTFILE")
	leKeyFile := os.Getenv("SSL_LE_KEYFILE")
	if leCertFile != "" && leKeyFile != "" {
		loaded, err := tls.LoadX509KeyPair(leCertFile, leKeyFile)
		if err != nil {
			// LE cert is optional - log and continue with default only.
			fmt.Printf("id1: warning: failed to load LE cert, using default only: %v\n", err)
		} else {
			leCert = &loaded
		}
	}

	cfg := &tls.Config{
		// NextProtos must explicitly list only http/1.1.
		// Without this, Go's HTTP server auto-adds "h2" (HTTP/2) to ALPN.
		// HTTP/2 strips the Connection and Upgrade headers, making WebSocket
		// upgrade impossible (RFC 6455 requires HTTP/1.1). Setting this
		// ensures cloudflared and other clients negotiate HTTP/1.1 only.
		NextProtos: []string{"http/1.1"},
		ClientAuth: tls.VerifyClientCertIfGiven,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if leCert == nil {
				return &defaultCert, nil
			}
			domain := os.Getenv("CURATORIUM_DOMAIN")
			if domain == "" {
				// An LE cert is configured but there is no domain to scope it -
				// refuse rather than guess a default suffix or match every SNI
				// via a bare empty-string suffix comparison.
				return nil, fmt.Errorf("id1: CURATORIUM_DOMAIN must be set to serve the configured Let's Encrypt certificate")
			}
			if strings.HasSuffix(hello.ServerName, "."+domain) {
				return leCert, nil
			}
			return &defaultCert, nil
		},
	}

	// Always set ClientCAs (an EMPTY pool when no CA is configured) so a presented
	// client cert is verified against THIS pool, never the host system root pool.
	// Leaving it nil makes VerifyClientCertIfGiven fall back to system roots, which
	// would fail OPEN to any web-PKI cert on client-cert-gated endpoints. An empty
	// pool fails closed (no presented cert verifies); a certless client still connects.
	pool := x509.NewCertPool()
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("id1: failed to read CA cert: %w", err)
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("id1: failed to parse CA cert")
		}
	}
	cfg.ClientCAs = pool

	return cfg, nil
}

// BuildTLSTransport builds an *http.Transport configured for mTLS client auth.
// Returns nil when MTLS_ENABLED is not "true" (use default transport).
func BuildTLSTransport() (*http.Transport, error) {
	if os.Getenv("MTLS_ENABLED") != "true" {
		return nil, nil
	}

	certFile := os.Getenv("SSL_CERTFILE")
	keyFile := os.Getenv("SSL_KEYFILE")
	caFile := os.Getenv("SSL_CA_CERTS")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("id1: failed to load TLS cert/key for transport: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("id1: failed to read CA cert for transport: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("id1: failed to parse CA cert for transport")
		}
		tlsCfg.RootCAs = pool
	}

	return &http.Transport{TLSClientConfig: tlsCfg}, nil
}
