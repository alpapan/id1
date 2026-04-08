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
//   - SSL_LE_CERTFILE / SSL_LE_KEYFILE: optional Let's Encrypt cert (for *.curatorium.app)
//
// When both certs are available, GetCertificate selects the LE cert for
// *.curatorium.app SNI and the cert-manager cert for everything else.
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
			// LE cert is optional — log and continue with default only.
			fmt.Printf("id1: warning: failed to load LE cert, using default only: %v\n", err)
		} else {
			leCert = &loaded
		}
	}

	cfg := &tls.Config{
		ClientAuth: tls.VerifyClientCertIfGiven,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if leCert != nil && strings.HasSuffix(hello.ServerName, ".curatorium.app") {
				return leCert, nil
			}
			return &defaultCert, nil
		},
	}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("id1: failed to read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("id1: failed to parse CA cert")
		}
		cfg.ClientCAs = pool
	}

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
