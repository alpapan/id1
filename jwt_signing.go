package id1

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
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

// KVPaths for JWT signing keys
const (
	privKeyPath        = "_system/priv/jwt-signing-key"
	pubKeyPath         = "_system/pub/jwt-signing-key"
	privKeyPrevPath    = "_system/priv/jwt-signing-key-prev"
	pubKeyPrevPath     = "_system/pub/jwt-signing-key-prev"
	jwtAudience        = "curatorium-backend"
	jwtIssuer          = "http://id1-router:8080"  // Internal Kubernetes DNS for id1
	jwtExpirationHours = 1
)

// GetOrCreateSigningKey loads RSA-2048 key from KV store or creates new one.
// Stores private key at _system/priv/jwt-signing-key (PEM).
// Stores public key at _system/pub/jwt-signing-key (PEM).
// Returns (keyID, privateKey, error). Key ID is SHA-256 JWK Thumbprint (RFC 7638).
func GetOrCreateSigningKey(kvStore KeyValueStore) (string, *rsa.PrivateKey, error) {
	// Try to load existing private key
	privPEM, err := kvStore.CmdGet(privKeyPath)
	if err == nil && len(privPEM) > 0 {
		privKey, err := parsePrivateKey(privPEM)
		if err == nil {
			keyID := computeKeyID(&privKey.PublicKey)
			return keyID, privKey, nil
		}
		// If parsing fails, generate new key
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

	// Store keys
	if err := kvStore.CmdSet(privKeyPath, privPEM); err != nil {
		return "", nil, fmt.Errorf("failed to store private key: %w", err)
	}
	if err := kvStore.CmdSet(pubKeyPath, pubPEM); err != nil {
		return "", nil, fmt.Errorf("failed to store public key: %w", err)
	}

	keyID := computeKeyID(&privateKey.PublicKey)
	return keyID, privateKey, nil
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
func getJWKS(kvStore KeyValueStore) ([]byte, error) {
	jwks := JWKS{Keys: []JWK{}}

	// Get current public key
	currentPubPEM, err := kvStore.CmdGet(pubKeyPath)
	if err == nil && len(currentPubPEM) > 0 {
		if jwk, err := pemToJWK(currentPubPEM); err == nil {
			jwk.Use = "sig"
			jwk.Alg = "RS256"
			jwks.Keys = append(jwks.Keys, *jwk)
		}
	}

	// Get previous public key (for rotation overlap)
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
