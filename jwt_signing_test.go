package id1

import (
	"encoding/json"
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
	t.Cleanup(func() { dbpath = originalDbpath })
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

// __END_OF_FILE_MARKER__
