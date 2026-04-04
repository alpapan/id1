package id1

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// BuildTLSConfig builds a *tls.Config when MTLS_ENABLED=true.
// Returns nil when mTLS is disabled (plain HTTP).
// Uses VerifyClientCertIfGiven (not RequireAndVerifyClientCert) because
// id1 is the LoadBalancer entry point — browsers cannot present cluster certs.
func BuildTLSConfig() (*tls.Config, error) {
	if os.Getenv("MTLS_ENABLED") != "true" {
		return nil, nil
	}

	certFile := os.Getenv("SSL_CERTFILE")
	keyFile := os.Getenv("SSL_KEYFILE")
	caFile := os.Getenv("SSL_CA_CERTS")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("id1: failed to load TLS cert/key: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
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
