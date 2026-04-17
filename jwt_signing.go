package id1

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// KeyValueStore defines the interface for key-value storage operations.
// It mirrors id1's existing CmdGet and CmdSet function signatures.
type KeyValueStore interface {
	CmdGet(key string) ([]byte, error)
	CmdSet(key string, value []byte) error
}

// ID1KeyValueStore implements KeyValueStore using id1's actual KV operations.
type ID1KeyValueStore struct{}

func (ID1KeyValueStore) CmdGet(key string) ([]byte, error) {
	return CmdGet(K(key)).Exec()
}

func (ID1KeyValueStore) CmdSet(key string, value []byte) error {
	_, err := CmdSet(K(key), map[string]string{}, value).Exec()
	return err
}

// HandleJWKS returns an HTTP handler that serves the JWKS endpoint.
func HandleJWKS(kvStore KeyValueStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		jwksBytes, err := getJWKS(kvStore)
		if err != nil {
			http.Error(w, "Failed to get JWKS", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBytes)
	}
}

// HandleTestUser returns an HTTP handler that issues a test JWT.
// This endpoint is only registered when ENV=test.
// It uses the same signing infrastructure as the ORCID callback.
func HandleTestUser(kvStore KeyValueStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		orcidID := r.URL.Query().Get("orcid")
		if orcidID == "" {
			orcidID = "0000-0002-1825-0097"
		}

		// Validate ORCID format
		if !orcidIDPattern.MatchString(orcidID) {
			http.Error(w, "Invalid ORCID iD format", http.StatusBadRequest)
			return
		}

		keyID, privKey, err := GetOrCreateSigningKey(kvStore)
		if err != nil {
			http.Error(w, "Failed to get signing key", http.StatusInternalServerError)
			return
		}

		jwtToken, err := signJWT(orcidID, privKey, keyID)
		if err != nil {
			http.Error(w, "Failed to sign JWT", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jwt":%q}`, jwtToken)
	}
}

// demoUserORCID is the ORCID of the seeded demo_user (99d_seed_demo_user.sql, id=10).
const demoUserORCID = "0009-0002-8023-3658"

// HandleDemoUser returns an HTTP handler that issues a JWT for the demo_user account.
// Registered at /auth/unauth_demo when ENV=test.
// This enables the demo/blast-live page to submit real BLAST jobs without ORCID login.
func HandleDemoUser(kvStore KeyValueStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		keyID, privKey, err := GetOrCreateSigningKey(kvStore)
		if err != nil {
			http.Error(w, "Failed to get signing key", http.StatusInternalServerError)
			return
		}
		jwtToken, err := signJWT(demoUserORCID, privKey, keyID)
		if err != nil {
			http.Error(w, "Failed to sign JWT", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		cors(&w)
		fmt.Fprintf(w, `{"jwt":%q}`, jwtToken)
	}
}

// KVPaths for JWT signing keys
const (
	privKeyPath        = "_system/priv/jwt-signing-key"
	pubKeyPath         = "_system/pub/jwt-signing-key"
	privKeyPrevPath    = "_system/priv/jwt-signing-key-prev"
	pubKeyPrevPath     = "_system/pub/jwt-signing-key-prev"
	jwtAudience        = "curatorium-backend"
	jwtIssuer          = "http://id1-router:8080" // Internal Kubernetes DNS for id1
	jwtExpirationHours = 1
)

// _memKey caches the generated signing key in memory when KV storage is unavailable
// (no emptyDir under Shape B). All requests within a pod's lifetime use the same key;
// the next restart picks up the key from ID1_JWT_PRIVATE_KEY (patched into K8s Secret).
var (
	_memKeyMu   sync.Mutex
	_memKeyID   string
	_memPrivKey *rsa.PrivateKey
)

// GetOrCreateSigningKey returns the id1 JWT signing key, preferring the env
// var populated from the curatorium-secrets Secret, then falling back to the
// KV store (legacy transitional path), then generating + persisting if absent
// everywhere. Returns (keyID, privateKey, error). Key ID is SHA-256 JWK
// Thumbprint (RFC 7638).
//
// Priority order:
//  1. ID1_JWT_PRIVATE_KEY env var (PEM) + ID1_JWT_KEY_ID env var — new primary
//  2. KV store (_system/priv/jwt-signing-key) — legacy fallback
//  3. Generate new key, store in both KV + patch curatorium-secrets
func GetOrCreateSigningKey(kvStore KeyValueStore) (string, *rsa.PrivateKey, error) {
	// 1. Prefer env vars populated from curatorium-secrets.
	// This makes JWT keys survive an id1 pod restart without needing the KV
	// store on persistent storage — the K8s Secret is the durable ground truth.
	if envPEM := os.Getenv("ID1_JWT_PRIVATE_KEY"); envPEM != "" {
		keyID := os.Getenv("ID1_JWT_KEY_ID")
		if keyID == "" {
			return "", nil, fmt.Errorf("ID1_JWT_PRIVATE_KEY set but ID1_JWT_KEY_ID empty")
		}
		privKey, err := parsePrivateKey([]byte(envPEM))
		if err != nil {
			return "", nil, fmt.Errorf("parse ID1_JWT_PRIVATE_KEY: %w", err)
		}
		return keyID, privKey, nil
	}

	// 1.5. In-memory cache — populated by path 3 when KV is unavailable (no emptyDir).
	// Ensures the same key is used for all requests within this pod's lifetime.
	_memKeyMu.Lock()
	if _memPrivKey != nil {
		id, key := _memKeyID, _memPrivKey
		_memKeyMu.Unlock()
		return id, key, nil
	}
	_memKeyMu.Unlock()

	// 2. Fallback: KV store (legacy path for installs predating env-var primacy).
	privPEM, err := kvStore.CmdGet(privKeyPath)
	if err == nil && len(privPEM) > 0 {
		privKey, err := parsePrivateKey(privPEM)
		if err == nil {
			keyID := computeKeyID(&privKey.PublicKey)
			return keyID, privKey, nil
		}
		// If parsing fails, generate new key below.
	}

	// Generate new RSA-2048 key pair
	privateKey, err := rsa.GenerateKey(cryptoRandReader, 2048)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key to PEM
	privPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Encode public key to PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubBytes,
	})

	// Store keys in KV (non-fatal: KV may be unavailable under Shape B with no emptyDir).
	if err := kvStore.CmdSet(privKeyPath, privPEM); err != nil {
		fmt.Printf("warning: failed to store private key in KV (no emptyDir?): %v\n", err)
	}
	if err := kvStore.CmdSet(pubKeyPath, pubPEM); err != nil {
		fmt.Printf("warning: failed to store public key in KV (no emptyDir?): %v\n", err)
	}

	keyID := computeKeyID(&privateKey.PublicKey)

	// Cache in memory so all requests within this pod's lifetime sign with the same key.
	_memKeyMu.Lock()
	_memKeyID = keyID
	_memPrivKey = privateKey
	_memKeyMu.Unlock()

	// Store key to Kubernetes Secret for test access
	if err := storeKeyToKubeSecret(privPEM, keyID); err != nil {
		// Log error but don't fail - KV store is primary
		fmt.Printf("warning: failed to store key to kube secret: %v\n", err)
	}

	return keyID, privateKey, nil
}

// storeKeyToKubeSecret stores the private key and key ID to Kubernetes Secret
// using the in-cluster service account credentials. No kubectl binary required.
// The id1 ServiceAccount must have RBAC permission to patch curatorium-secrets.
func storeKeyToKubeSecret(privPEM []byte, keyID string) error {
	namespace := os.Getenv("CURATORIUM_NAMESPACE")
	if namespace == "" {
		namespace = "curatorium-test"
	}

	// Read in-cluster service account token (auto-mounted by Kubernetes)
	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return fmt.Errorf("not running in a Kubernetes cluster (no service account token): %w", err)
	}

	// Read the cluster CA certificate to verify the API server
	caCertBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return fmt.Errorf("failed to read cluster CA cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertBytes) {
		return fmt.Errorf("failed to parse cluster CA cert")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caCertPool},
		},
		Timeout: 10 * time.Second,
	}

	apiHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	apiPort := os.Getenv("KUBERNETES_SERVICE_PORT")
	if apiHost == "" || apiPort == "" {
		apiHost = "kubernetes.default.svc"
		apiPort = "443"
	}

	privKeyB64 := base64.StdEncoding.EncodeToString(privPEM)
	keyIDB64 := base64.StdEncoding.EncodeToString([]byte(keyID))
	patch := fmt.Sprintf(`{"data":{"ID1_JWT_PRIVATE_KEY":"%s","ID1_JWT_KEY_ID":"%s"}}`,
		privKeyB64, keyIDB64)

	apiURL := fmt.Sprintf("https://%s:%s/api/v1/namespaces/%s/secrets/curatorium-secrets",
		apiHost, apiPort, namespace)

	req, err := http.NewRequest(http.MethodPatch, apiURL, strings.NewReader(patch))
	if err != nil {
		return fmt.Errorf("failed to create PATCH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/merge-patch+json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tokenBytes)))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to patch Kubernetes Secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Kubernetes API returned %d: %s", resp.StatusCode, body)
	}

	return nil
}

// parsePrivateKey parses a PEM-encoded RSA private key.
func parsePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// signJWT issues RS256 JWT with claims: iss, sub, aud="curatorium-backend", iat, exp=iat+3600, kid.
func signJWT(orcidID string, privateKey *rsa.PrivateKey, keyID string) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    jwtIssuer,
		Subject:   orcidID,
		Audience:  jwt.ClaimStrings{jwtAudience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour * jwtExpirationHours)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	return token.SignedString(privateKey)
}

// ValidateRS256JWT verifies an RS256 JWT signed by id1's own signing key.
// Used by sovereign register endpoints to authenticate re-registration requests.
// Returns jwt.RegisteredClaims (not the custom auth.Claims struct) because ORCID
// JWTs don't carry the Username field — only Subject (ORCID iD) matters here.
func ValidateRS256JWT(tokenStr string, kvStore KeyValueStore) (jwt.RegisteredClaims, error) {
	pubPEM, err := kvStore.CmdGet(pubKeyPath)
	if err != nil || len(pubPEM) == 0 {
		return jwt.RegisteredClaims{}, fmt.Errorf("no signing public key found")
	}

	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return jwt.RegisteredClaims{}, fmt.Errorf("failed to decode public key PEM")
	}

	pubKeyIface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return jwt.RegisteredClaims{}, fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaPubKey, ok := pubKeyIface.(*rsa.PublicKey)
	if !ok {
		return jwt.RegisteredClaims{}, fmt.Errorf("public key is not RSA")
	}

	var claims jwt.RegisteredClaims
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return rsaPubKey, nil
	})
	if err != nil {
		return claims, fmt.Errorf("JWT validation failed: %w", err)
	}
	if !token.Valid {
		return claims, fmt.Errorf("JWT is not valid")
	}
	return claims, nil
}

// rotateSigningKey moves current key to _system/priv/jwt-signing-key-prev and
// _system/pub/jwt-signing-key-prev, then generates a new current key.
// Previous key remains in JWKS for 1-hour overlap to allow in-flight JWTs to validate.
func rotateSigningKey(kvStore KeyValueStore) error {
	// Get current private key
	privPEM, err := kvStore.CmdGet(privKeyPath)
	if err != nil || len(privPEM) == 0 {
		return fmt.Errorf("no existing private key to rotate")
	}

	// Get current public key
	pubPEM, err := kvStore.CmdGet(pubKeyPath)
	if err != nil || len(pubPEM) == 0 {
		return fmt.Errorf("no existing public key to rotate")
	}

	// Store current keys as previous
	if err := kvStore.CmdSet(privKeyPrevPath, privPEM); err != nil {
		return fmt.Errorf("failed to store previous private key: %w", err)
	}
	if err := kvStore.CmdSet(pubKeyPrevPath, pubPEM); err != nil {
		return fmt.Errorf("failed to store previous public key: %w", err)
	}

	// Generate new key pair
	privateKey, err := rsa.GenerateKey(cryptoRandReader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate new RSA key: %w", err)
	}

	// Encode new keys to PEM
	newPrivPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	newPubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal new public key: %w", err)
	}
	newPubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: newPubBytes,
	})

	// Store new keys at primary paths
	if err := kvStore.CmdSet(privKeyPath, newPrivPEM); err != nil {
		return fmt.Errorf("failed to store new private key: %w", err)
	}
	if err := kvStore.CmdSet(pubKeyPath, newPubPEM); err != nil {
		return fmt.Errorf("failed to store new public key: %w", err)
	}

	return nil
}

// JWK represents a JSON Web Key (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

// JWKS represents a JSON Web Key Set (RFC 7517).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// getJWKS returns JSON Web Key Set with current and previous public keys.
// Served at GET /pub/jwks.json.
//
// Under Shape B the JWT key is sourced from the ID1_JWT_PRIVATE_KEY env var
// populated from K8s Secret; the KV store may be empty (or unwritable if
// the /mnt emptyDir was removed). In that case we derive the public JWK
// directly from the env-loaded private key so the JWKS endpoint still
// publishes the current signer. The KV paths remain the fallback for the
// legacy path and for the rotation-overlap "previous" key.
func getJWKS(kvStore KeyValueStore) ([]byte, error) {
	jwks := JWKS{Keys: []JWK{}}

	// Prefer env-loaded private key (Shape B primary path): derive public JWK
	// directly rather than looking it up in the (possibly empty) KV store.
	if envPEM := os.Getenv("ID1_JWT_PRIVATE_KEY"); envPEM != "" {
		keyID := os.Getenv("ID1_JWT_KEY_ID")
		if privKey, err := parsePrivateKey([]byte(envPEM)); err == nil && keyID != "" {
			jwks.Keys = append(jwks.Keys, JWK{
				Kty: "RSA",
				Kid: keyID,
				Use: "sig",
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
			})
		}
	} else {
		// Memory cache: populated under Shape B when KV is unavailable.
		_memKeyMu.Lock()
		memKey := _memPrivKey
		memID := _memKeyID
		_memKeyMu.Unlock()
		if memKey != nil && memID != "" {
			jwks.Keys = append(jwks.Keys, JWK{
				Kty: "RSA",
				Kid: memID,
				Use: "sig",
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(memKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(memKey.E)).Bytes()),
			})
		} else {
			// Legacy path: read current public key from KV store.
			currentPubPEM, err := kvStore.CmdGet(pubKeyPath)
			if err == nil && len(currentPubPEM) > 0 {
				if jwk, err := pemToJWK(currentPubPEM); err == nil {
					jwk.Use = "sig"
					jwk.Alg = "RS256"
					jwks.Keys = append(jwks.Keys, *jwk)
				}
			}
		}
	}

	// Previous public key (for rotation overlap) always comes from KV.
	prevPubPEM, err := kvStore.CmdGet(pubKeyPrevPath)
	if err == nil && len(prevPubPEM) > 0 {
		if jwk, err := pemToJWK(prevPubPEM); err == nil {
			jwk.Use = "sig"
			jwk.Alg = "RS256"
			jwks.Keys = append(jwks.Keys, *jwk)
		}
	}

	return json.Marshal(jwks)
}

// pemToJWK converts a PEM-encoded public key to JWK format.
func pemToJWK(pemData []byte) (*JWK, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	kid := computeKeyID(rsaPubKey)

	return &JWK{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(rsaPubKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPubKey.E)).Bytes()),
	}, nil
}

// computeKeyID computes SHA-256 JWK Thumbprint (RFC 7638) from public key.
// Returns base64url-encoded 43-character string.
func computeKeyID(pubKey *rsa.PublicKey) string {
	// RFC 7638 JWK Thumbprint for RSA key
	// The input is the JWK representation of the key
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
	}

	// Canonicalize using JSON deterministic serialization
	// We need the precise RFC 7638 format: {"e":"...","kty":"RSA","n":"..."}
	// Keys must be in lexicographic order
	jwkBytes := []byte(`{"e":"` + jwk["e"].(string) + `","kty":"RSA","n":"` + jwk["n"].(string) + `"}`)

	hash := sha256.Sum256(jwkBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// __END_OF_FILE_MARKER__
