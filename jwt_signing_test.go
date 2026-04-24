// apps/backend/containers/id1/jwt_signing_test.go
//
// group: jwt
// tags: jwt, signing, rs256, testing
// summary: Tests for RS256 JWT signing and JWKS generation.
//
//

package id1

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestKVStore creates a temporary database for test isolation.
// Returns KeyValueStore using real KV operations with isolated tmpdir.
func setupTestKVStore(t *testing.T) KeyValueStore {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	// Reset the in-memory key cache so each test starts with a clean slate.
	_memKeyMu.Lock()
	_memKeyID = ""
	_memPrivKey = nil
	_memKeyMu.Unlock()
	t.Cleanup(func() {
		dbpath = originalDbpath
		_memKeyMu.Lock()
		_memKeyID = ""
		_memPrivKey = nil
		_memKeyMu.Unlock()
	})
	return ID1KeyValueStore{}
}

func TestGetOrCreateSigningKey_CreatesKeyOnFirstCall(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, privKey, err := GetOrCreateSigningKey(kv)

	require.NoError(t, err)
	assert.NotEmpty(t, keyID)
	assert.NotNil(t, privKey)
	assert.Equal(t, 2048, privKey.N.BitLen(), "Key should be RSA-2048")

	// Verify private key stored at correct path in real KV store
	storedPrivBytes, err := kv.CmdGet("_system/priv/jwt-signing-key")
	require.NoError(t, err)
	assert.NotNil(t, storedPrivBytes, "Private key should be stored at _system/priv/jwt-signing-key")

	// Verify public key stored at correct path in real KV store
	storedPubBytes, err := kv.CmdGet("_system/pub/jwt-signing-key")
	require.NoError(t, err)
	assert.NotNil(t, storedPubBytes, "Public key should be stored at _system/pub/jwt-signing-key")
}

func TestGetOrCreateSigningKey_ReturnsExistingKey(t *testing.T) {
	kv := setupTestKVStore(t)

	keyID1, privKey1, err1 := GetOrCreateSigningKey(kv)
	require.NoError(t, err1)

	keyID2, privKey2, err2 := GetOrCreateSigningKey(kv)
	require.NoError(t, err2)

	// Both calls should return the same key from persistent storage
	assert.Equal(t, keyID1, keyID2, "Key IDs should match on subsequent calls")
	assert.Equal(t, privKey1.D, privKey2.D, "Private key components should match")
}

func TestSignJWT_RS256Valid(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, privKey, _ := GetOrCreateSigningKey(kv)

	orcidID := "0000-0001-2345-6789"
	tokenString, err := signJWT(orcidID, privKey, keyID)

	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Parse and verify JWT structure
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return &privKey.PublicKey, nil
	})

	require.NoError(t, err)
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	require.True(t, ok)

	assert.Equal(t, orcidID, claims.Subject)
	assert.Equal(t, "curatorium-backend", claims.Audience[0])
	assert.True(t, time.Now().Before(time.Unix(claims.ExpiresAt.Unix(), 0)))
}

func TestSignJWT_HasCorrectKeyID(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, privKey, _ := GetOrCreateSigningKey(kv)

	tokenString, _ := signJWT("0000-0001-2345-6789", privKey, keyID)

	// Parse header to verify kid
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privKey.PublicKey, nil
	})

	kid, ok := token.Header["kid"].(string)
	require.True(t, ok)
	assert.Equal(t, keyID, kid)
}

func TestRotateSigningKey_KeepsPreviousKey(t *testing.T) {
	kv := setupTestKVStore(t)

	// Create initial key
	_, _, _ = GetOrCreateSigningKey(kv)
	storedPrivKey1, err := kv.CmdGet("_system/priv/jwt-signing-key")
	require.NoError(t, err)
	storedPubKey1, err := kv.CmdGet("_system/pub/jwt-signing-key")
	require.NoError(t, err)

	// Rotate
	err = rotateSigningKey(kv)
	require.NoError(t, err)

	// Verify new key exists at primary path
	storedPrivKey2, err := kv.CmdGet("_system/priv/jwt-signing-key")
	require.NoError(t, err)
	assert.NotNil(t, storedPrivKey2)
	assert.NotEqual(t, storedPrivKey1, storedPrivKey2, "Private key should be different after rotation")

	// Verify previous private key saved at -prev path
	storedPrivKeyPrev, err := kv.CmdGet("_system/priv/jwt-signing-key-prev")
	require.NoError(t, err)
	assert.Equal(t, storedPrivKey1, storedPrivKeyPrev, "Previous private key should be at _system/priv/jwt-signing-key-prev")

	// Verify previous public key saved at -prev path
	storedPubKeyPrev, err := kv.CmdGet("_system/pub/jwt-signing-key-prev")
	require.NoError(t, err)
	assert.Equal(t, storedPubKey1, storedPubKeyPrev, "Previous public key should be at _system/pub/jwt-signing-key-prev")
}

func TestGetJWKS_ReturnsBothKeysDuringRotationOverlap(t *testing.T) {
	kv := setupTestKVStore(t)

	GetOrCreateSigningKey(kv)
	rotateSigningKey(kv)

	jwksBytes, err := getJWKS(kv)
	require.NoError(t, err)

	var jwks map[string]interface{}
	err = json.Unmarshal(jwksBytes, &jwks)
	require.NoError(t, err)

	keys, ok := jwks["keys"].([]interface{})
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(keys), 2, "JWKS should contain current and previous keys during rotation overlap")
}

func TestGetJWKS_ReturnsOnlyCurrentKeyWhenNoPrev(t *testing.T) {
	kv := setupTestKVStore(t)

	GetOrCreateSigningKey(kv)

	jwksBytes, err := getJWKS(kv)
	require.NoError(t, err)

	var jwks map[string]interface{}
	err = json.Unmarshal(jwksBytes, &jwks)
	require.NoError(t, err)

	keys, ok := jwks["keys"].([]interface{})
	require.True(t, ok)
	assert.Equal(t, 1, len(keys), "JWKS should contain only current key when no previous key exists")
}

func TestKeyIDFormat_IsSHA256Thumbprint(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, _, _ := GetOrCreateSigningKey(kv)

	// SHA-256 thumbprint base64url-encoded = 43 chars (256 bits / 6 bits per char, no padding)
	assert.Equal(t, 43, len(keyID), "SHA-256 thumbprint should be 43 base64url chars")

	// Should only contain base64url characters (no +, /, or =)
	for _, ch := range keyID {
		assert.True(t, (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') || ch == '-' || ch == '_',
			"Key ID should be base64url encoded (no +, /, or = padding)")
	}
}

func TestHandleDemoUser(t *testing.T) {
	kvStore := setupTestKVStore(t)

	handler := HandleDemoUser(kvStore)

	t.Run("GET returns JWT for demo_user ORCID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/unauth_demo", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if resp["jwt"] == "" {
			t.Fatal("expected non-empty jwt")
		}

		// Validate JWT is cryptographically valid and contains correct claims
		_, privKey, err := GetOrCreateSigningKey(kvStore) // same kvStore as the handler used
		if err != nil {
			t.Fatalf("failed to get signing key: %v", err)
		}
		token, parseErr := jwt.ParseWithClaims(resp["jwt"], &jwt.RegisteredClaims{}, func(tok *jwt.Token) (interface{}, error) {
			return &privKey.PublicKey, nil
		})
		if parseErr != nil {
			t.Fatalf("JWT should be cryptographically valid: %v", parseErr)
		}
		claims, ok := token.Claims.(*jwt.RegisteredClaims)
		if !ok {
			t.Fatal("claims should be RegisteredClaims")
		}
		if claims.Subject != demoUserORCID {
			t.Errorf("expected subject %q, got %q", demoUserORCID, claims.Subject)
		}
	})

	t.Run("POST returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/unauth_demo", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", w.Code)
		}
	})
}

func TestValidateRS256JWT(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, privKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)

	t.Run("valid JWT returns correct claims", func(t *testing.T) {
		tokenStr, err := signJWT("0000-0001-2345-6789", privKey, keyID)
		require.NoError(t, err)

		claims, err := ValidateRS256JWT(tokenStr, kv)
		require.NoError(t, err)
		assert.Equal(t, "0000-0001-2345-6789", claims.Subject)
	})

	t.Run("garbage token fails", func(t *testing.T) {
		_, err := ValidateRS256JWT("garbage.token.here", kv)
		assert.Error(t, err)
	})

	t.Run("expired token fails", func(t *testing.T) {
		expiredClaims := jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			Subject:   "0000-0001-2345-6789",
			Audience:  jwt.ClaimStrings{jwtAudience},
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		}
		expiredToken := jwt.NewWithClaims(jwt.SigningMethodRS256, expiredClaims)
		expiredToken.Header["kid"] = keyID
		expiredStr, _ := expiredToken.SignedString(privKey)

		_, err := ValidateRS256JWT(expiredStr, kv)
		assert.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// K8s-Secret-primary JWT key loading (Task 8).
// ---------------------------------------------------------------------------

// memoryKV is a test double implementing KeyValueStore with in-memory storage.
type memoryKV struct {
	store map[string][]byte
}

func (m *memoryKV) CmdGet(key string) ([]byte, error) {
	if m.store == nil {
		return nil, nil
	}
	return m.store[key], nil
}

func (m *memoryKV) CmdSet(key string, value []byte) error {
	if m.store == nil {
		m.store = map[string][]byte{}
	}
	m.store[key] = value
	return nil
}

func TestGetOrCreateSigningKey_ReadsFromEnvFirst(t *testing.T) {
	// Generate a key, PEM-encode it (matches what curatorium-secrets provides).
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})
	keyID := computeKeyID(&privKey.PublicKey)

	t.Setenv("ID1_JWT_PRIVATE_KEY", string(privPEM))
	t.Setenv("ID1_JWT_KEY_ID", keyID)

	// Use an empty KV store so we know the key came from env.
	kv := &memoryKV{}

	gotKeyID, gotKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)
	assert.Equal(t, keyID, gotKeyID, "key ID must match env")
	assert.Equal(t, privKey.N.String(), gotKey.N.String(), "RSA modulus must match env-loaded key")
}

func TestGetOrCreateSigningKey_EnvPrivateKeyWithoutKeyIDErrors(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})

	t.Setenv("ID1_JWT_PRIVATE_KEY", string(privPEM))
	t.Setenv("ID1_JWT_KEY_ID", "")

	kv := &memoryKV{}
	_, _, err = GetOrCreateSigningKey(kv)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ID1_JWT_KEY_ID")
}

func TestGetOrCreateSigningKey_EnvInvalidPEMErrors(t *testing.T) {
	t.Setenv("ID1_JWT_PRIVATE_KEY", "not-a-pem-block")
	t.Setenv("ID1_JWT_KEY_ID", "some-kid")

	kv := &memoryKV{}
	_, _, err := GetOrCreateSigningKey(kv)
	require.Error(t, err)
}

func TestValidateRS256JWT_UsesEnvVarPublicKey(t *testing.T) {
	// Reset memory cache so env var path is the only source.
	_memKeyMu.Lock()
	_memKeyID = ""
	_memPrivKey = nil
	_memKeyMu.Unlock()
	t.Cleanup(func() {
		_memKeyMu.Lock()
		_memKeyID = ""
		_memPrivKey = nil
		_memKeyMu.Unlock()
	})

	// Generate a key and install it via env var (Shape B path).
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})
	keyID := computeKeyID(&privKey.PublicKey)
	t.Setenv("ID1_JWT_PRIVATE_KEY", string(privPEM))
	t.Setenv("ID1_JWT_KEY_ID", keyID)

	// Sign a JWT with that key.
	tokenStr, err := signJWT("0000-0001-2345-6789", privKey, keyID)
	require.NoError(t, err)

	// Validate against an EMPTY KV store — validation must use the env var.
	emptyKV := &memoryKV{}
	claims, err := ValidateRS256JWT(tokenStr, emptyKV)
	require.NoError(t, err, "validation must succeed via env var public key when KV is empty")
	assert.Equal(t, "0000-0001-2345-6789", claims.Subject)
}

func TestValidateRS256JWT_UsesMemoryCachePublicKey(t *testing.T) {
	// Reset memory cache
	_memKeyMu.Lock()
	_memKeyID = ""
	_memPrivKey = nil
	_memKeyMu.Unlock()
	t.Cleanup(func() {
		_memKeyMu.Lock()
		_memKeyID = ""
		_memPrivKey = nil
		_memKeyMu.Unlock()
	})

	// Populate the in-memory cache (simulating path 3 fallback).
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyID := computeKeyID(&privKey.PublicKey)
	_memKeyMu.Lock()
	_memKeyID = keyID
	_memPrivKey = privKey
	_memKeyMu.Unlock()

	// Sign a JWT with the cached key.
	tokenStr, err := signJWT("0000-0001-5555-6666", privKey, keyID)
	require.NoError(t, err)

	// Validate against an empty KV store — must use memory cache.
	emptyKV := &memoryKV{}
	claims, err := ValidateRS256JWT(tokenStr, emptyKV)
	require.NoError(t, err)
	assert.Equal(t, "0000-0001-5555-6666", claims.Subject)
}

// failingKVStore simulates KV store unavailability (no emptyDir under Shape B).
type failingKVStore struct{}

func (f *failingKVStore) CmdGet(key string) ([]byte, error) {
	return nil, fmt.Errorf("no storage")
}
func (f *failingKVStore) CmdSet(key string, value []byte) error {
	return fmt.Errorf("no storage")
}

func TestGetOrCreateSigningKey_KVUnavailableUsesMemoryCache(t *testing.T) {
	// Reset memory cache at start and in cleanup (package-level state).
	_memKeyMu.Lock()
	_memKeyID = ""
	_memPrivKey = nil
	_memKeyMu.Unlock()
	t.Cleanup(func() {
		_memKeyMu.Lock()
		_memKeyID = ""
		_memPrivKey = nil
		_memKeyMu.Unlock()
	})

	store := &failingKVStore{}

	keyID1, key1, err := GetOrCreateSigningKey(store)
	if err != nil {
		t.Fatalf("expected no error even with failing KV, got: %v", err)
	}
	if keyID1 == "" {
		t.Fatal("expected non-empty keyID")
	}

	// Second call must return the same key (memory cache, not re-generate).
	keyID2, key2, err := GetOrCreateSigningKey(store)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if keyID1 != keyID2 {
		t.Errorf("expected same keyID across calls, got %q vs %q", keyID1, keyID2)
	}
	if key1 != key2 {
		t.Error("expected same private key pointer from memory cache")
	}

	// JWKS must include the memory-cached key so the backend can validate JWTs.
	jwksBytes, err := getJWKS(store)
	if err != nil {
		t.Fatalf("getJWKS failed: %v", err)
	}
	var jwks JWKS
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		t.Fatalf("invalid JWKS JSON: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Error("expected JWKS to contain the memory-cached key")
	} else if jwks.Keys[0].Kid != keyID1 {
		t.Errorf("JWKS kid %q does not match generated key id %q", jwks.Keys[0].Kid, keyID1)
	}
}

func TestIsDevOrTestEnv(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"test", true},
		{"dev", true},
		{"prod", false},
		{"production", false},
		{"demo", false},
		{"staging", false},
		{"", false},
		{"Test", false},  // case-sensitive: "Test" ≠ "test"
		{" test", false}, // no whitespace normalisation
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("env=%q", tc.env), func(t *testing.T) {
			got := IsDevOrTestEnv(tc.env)
			assert.Equal(t, tc.want, got, "IsDevOrTestEnv(%q)", tc.env)
		})
	}
}

func TestHandleTestUser(t *testing.T) {
	kvStore := setupTestKVStore(t)
	handler := HandleTestUser(kvStore)

	t.Run("GET returns JWT for provided ORCID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/test_user?orcid=0000-0001-0000-0001", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if resp["jwt"] == "" {
			t.Fatal("expected non-empty jwt")
		}
		_, privKey, err := GetOrCreateSigningKey(kvStore)
		if err != nil {
			t.Fatalf("failed to get signing key: %v", err)
		}
		token, parseErr := jwt.ParseWithClaims(resp["jwt"], &jwt.RegisteredClaims{}, func(tok *jwt.Token) (interface{}, error) {
			return &privKey.PublicKey, nil
		})
		if parseErr != nil {
			t.Fatalf("JWT should be cryptographically valid: %v", parseErr)
		}
		claims, ok := token.Claims.(*jwt.RegisteredClaims)
		if !ok {
			t.Fatal("claims should be RegisteredClaims")
		}
		if claims.Subject != "0000-0001-0000-0001" {
			t.Errorf("expected subject %q, got %q", "0000-0001-0000-0001", claims.Subject)
		}
	})

	t.Run("GET with invalid ORCID returns 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/test_user?orcid=not-an-orcid", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("GET with no ORCID returns JWT with default ORCID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/test_user", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		_, privKey, err := GetOrCreateSigningKey(kvStore)
		if err != nil {
			t.Fatalf("failed to get signing key: %v", err)
		}
		token, parseErr := jwt.ParseWithClaims(resp["jwt"], &jwt.RegisteredClaims{}, func(tok *jwt.Token) (interface{}, error) {
			return &privKey.PublicKey, nil
		})
		if parseErr != nil {
			t.Fatalf("default-ORCID JWT should be cryptographically valid: %v", parseErr)
		}
		claims, ok := token.Claims.(*jwt.RegisteredClaims)
		if !ok {
			t.Fatal("claims should be RegisteredClaims")
		}
		const defaultORCID = "0000-0002-1825-0097"
		if claims.Subject != defaultORCID {
			t.Errorf("expected default ORCID %q as subject, got %q", defaultORCID, claims.Subject)
		}
	})

	t.Run("POST returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/test_user", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", w.Code)
		}
	})
}

// __END_OF_FILE_MARKER__
