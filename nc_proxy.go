// apps/id1/nc_proxy.go
//
// group: nextcloud
// tags: nextcloud, proxy, client-address, mtls
// summary: id1's reverse proxy to Nextcloud's id1-only port, stating the caller address.
//
//

package id1

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

// NoTraefikProofWarning is printed at start when MTLS_ENABLED is not "true". Without
// mTLS id1 cannot tell Traefik from any other pod that reaches its listener, and any
// such pod can set X-Real-Ip and CF-Connecting-IP to choose the address Nextcloud's
// brute-force protection counts.
const NoTraefikProofWarning = "" +
	"*****************************************************************************\n" +
	"WARNING: MTLS_ENABLED is not \"true\": id1 cannot prove a /nextcloud request\n" +
	"came from Traefik. Any pod that reaches id1 can set X-Real-Ip and\n" +
	"CF-Connecting-IP and so choose the caller address Nextcloud's brute-force\n" +
	"protection counts. Set MTLS_ENABLED=true in .env to require Traefik's\n" +
	"client certificate (traefik-id1-proxy-client).\n" +
	"*****************************************************************************"

// NextcloudProxyConfig is everything NewNextcloudProxyHandler needs. TraefikCA is nil
// when mTLS is off, and then no client certificate is required.
type NextcloudProxyConfig struct {
	TargetURL *url.URL
	Rule      ClientAddressRule
	TraefikCA *x509.Certificate
	Transport http.RoundTripper
}

// NewNextcloudProxyHandler returns the /nextcloud handler: it requires Traefik's client
// certificate (when TraefikCA is set), decides the caller address, states it in
// ClientAddressHeader and forwards the request with the /nextcloud prefix removed. A
// request accepted on ComputeProxyPort is decided by DecideComputeAddress (one address
// per account); every other request by cfg.Rule.
func NewNextcloudProxyHandler(cfg NextcloudProxyConfig) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(cfg.TargetURL)
	if cfg.Transport != nil {
		proxy.Transport = cfg.Transport
	}
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		req.URL.Path = strings.TrimPrefix(req.URL.Path, "/nextcloud")
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
		if req.URL.RawPath != "" {
			req.URL.RawPath = strings.TrimPrefix(req.URL.RawPath, "/nextcloud")
			if req.URL.RawPath == "" {
				req.URL.RawPath = "/"
			}
		}
		req.Host = cfg.TargetURL.Host
		originalDirector(req)
		log.Printf("[nextcloud-proxy] %s %s -> %s%s", req.Method, req.URL.Path, cfg.TargetURL.Host, req.URL.Path)
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[nextcloud-proxy] Error: %v", err)
		http.Error(w, "Nextcloud service unavailable", http.StatusBadGateway)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.TraefikCA != nil && !RequestFromTraefik(r.TLS, cfg.TraefikCA) {
			log.Printf("[nextcloud-proxy] refused %s %s: no Traefik client certificate (X-Real-Ip %q)", r.Method, r.URL.Path, r.Header.Get(traefikPeerHeader))
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		var decision ClientAddressDecision
		if arrivedOnComputePort(r) {
			decision = DecideComputeAddress(r)
		} else {
			decision = cfg.Rule.Decide(r.Context(), r.Header)
		}
		if decision.Status != 0 {
			log.Printf("[nextcloud-proxy] refused %s %s with %d: %s", r.Method, r.URL.Path, decision.Status, decision.Reason)
			http.Error(w, http.StatusText(decision.Status), decision.Status)
			return
		}
		ApplyClientAddress(r.Header, decision.Address)
		proxy.ServeHTTP(w, r)
	})
}

// ResolveNextcloudProxyConfig reads the proxy configuration through getenv. Every key
// it reads has no default; a missing or malformed value is an error naming the key.
//
//   - NEXTCLOUD_PROXY_URL: https URL of Nextcloud's id1-only port.
//   - EDGE_PROOF_METHOD: connector-address or edge-secret.
//   - CLUSTER_POD_CIDR: the pod range; an edge address inside it is refused.
//   - EDGE_PROOF_SECRET: required for edge-secret.
//   - TRAEFIK_PROXY_CA_FILE: required when MTLS_ENABLED is "true".
//   - NEXTCLOUD_CLIENT_CERT_FILE, NEXTCLOUD_CLIENT_KEY_FILE: id1's client certificate,
//     always required (the id1-only port requires it whatever MTLS_ENABLED says).
//   - NEXTCLOUD_SERVER_CA_FILE: the CA that signed Nextcloud's server certificate.
func ResolveNextcloudProxyConfig(getenv func(string) string) (NextcloudProxyConfig, error) {
	var cfg NextcloudProxyConfig
	target := getenv("NEXTCLOUD_PROXY_URL")
	if target == "" {
		return cfg, fmt.Errorf("id1: NEXTCLOUD_PROXY_URL is not set")
	}
	targetURL, err := url.Parse(target)
	if err != nil || targetURL.Scheme != "https" || targetURL.Host == "" {
		return cfg, fmt.Errorf("id1: NEXTCLOUD_PROXY_URL must be an https URL with a host, got %q", target)
	}
	method, err := ParseEdgeProofMethod(getenv("EDGE_PROOF_METHOD"))
	if err != nil {
		return cfg, err
	}
	podRange, err := netip.ParsePrefix(getenv("CLUSTER_POD_CIDR"))
	if err != nil {
		return cfg, fmt.Errorf("id1: CLUSTER_POD_CIDR must be a CIDR prefix, got %q: %w", getenv("CLUSTER_POD_CIDR"), err)
	}
	rule := ClientAddressRule{Method: method, PodRange: podRange.Masked()}
	switch method {
	case EdgeProofConnectorAddress:
		rule.Connectors = NewConnectorSet(CloudflaredConnectorsName)
	case EdgeProofEdgeSecret:
		secret := getenv("EDGE_PROOF_SECRET")
		if secret == "" {
			return cfg, fmt.Errorf("id1: EDGE_PROOF_SECRET is not set and EDGE_PROOF_METHOD is %q", EdgeProofEdgeSecret)
		}
		rule.EdgeSecret = secret
	}
	cfg.TargetURL = targetURL
	cfg.Rule = rule
	if getenv("MTLS_ENABLED") == "true" {
		caPath := getenv("TRAEFIK_PROXY_CA_FILE")
		if caPath == "" {
			return cfg, fmt.Errorf("id1: TRAEFIK_PROXY_CA_FILE is not set and MTLS_ENABLED is \"true\"")
		}
		ca, err := LoadCACertificate(caPath)
		if err != nil {
			return cfg, fmt.Errorf("id1: TRAEFIK_PROXY_CA_FILE: %w", err)
		}
		cfg.TraefikCA = ca
	}
	transport, err := buildNextcloudClientTransport(getenv("NEXTCLOUD_CLIENT_CERT_FILE"), getenv("NEXTCLOUD_CLIENT_KEY_FILE"), getenv("NEXTCLOUD_SERVER_CA_FILE"))
	if err != nil {
		return cfg, err
	}
	cfg.Transport = transport
	return cfg, nil
}

// buildNextcloudClientTransport returns a transport presenting id1's client certificate
// and trusting only the CA that signed Nextcloud's server certificate. It never uses an
// environment proxy.
func buildNextcloudClientTransport(certFile, keyFile, caFile string) (*http.Transport, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("id1: NEXTCLOUD_CLIENT_CERT_FILE and NEXTCLOUD_CLIENT_KEY_FILE must both be set: Nextcloud's id1-only port requires id1's client certificate")
	}
	if caFile == "" {
		return nil, fmt.Errorf("id1: NEXTCLOUD_SERVER_CA_FILE is not set")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("id1: NEXTCLOUD_CLIENT_CERT_FILE/NEXTCLOUD_CLIENT_KEY_FILE: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("id1: NEXTCLOUD_SERVER_CA_FILE: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("id1: NEXTCLOUD_SERVER_CA_FILE %s holds no PEM certificate", caFile)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = false
	transport.TLSClientConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	return transport, nil
}
