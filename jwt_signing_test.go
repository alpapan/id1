package id1

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockKeyValueStore wraps id1's CmdGet/CmdSet interface (k.go, cmd.go) with
// an in-memory map for test isolation. Implements the KeyValueStore interface.
type MockKeyValueStore struct {
	data map[string][]byte
}

func NewMockKVStore() *MockKeyValueStore {
	return &MockKeyValueStore{data: make(map[string][]byte)}
}

// CmdGet mirrors id1's existing CmdGet function signature from cmd.go.
func (m *MockKeyValueStore) CmdGet(key string) ([]byte, error) {
	if val, ok := m.data[key]; ok {
		return val, nil
	}
	return nil, nil
}

// CmdSet mirrors id1's existing CmdSet function signature from cmd.go.
func (m *MockKeyValueStore) CmdSet(key string, value []byte) error {
	m.data[key] = value
	return nil
}

func TestGetOrCreateSigningKey_CreatesKeyOnFirstCall(t *testing.T) {
	kv := NewMockKVStore()
	keyID, privKey, err := getOrCreateSigningKey(kv)

	require.NoError(t, err)
	assert.NotEmpty(t, keyID)
	assert.NotNil(t, privKey)
	assert.Equal(t, 2048, privKey.N.BitLen(), "Key should be RSA-2048")

	// Verify private key stored at correct path
	storedPrivBytes, _ := kv.CmdGet("_system/priv/jwt-signing-key")
	assert.NotNil(t, storedPrivBytes, "Private key should be stored at _system/priv/jwt-signing-key")

	// Verify public key stored at correct path
	storedPubBytes, _ := kv.CmdGet("_system/pub/jwt-signing-key")
	assert.NotNil(t, storedPubBytes, "Public key should be stored at _system/pub/jwt-signing-key")
}

func TestGetOrCreateSigningKey_ReturnsExistingKey(t *testing.T) {
	kv := NewMockKVStore()

	keyID1, privKey1, err1 := getOrCreateSigningKey(kv)
	require.NoError(t, err1)

	keyID2, privKey2, err2 := getOrCreateSigningKey(kv)
	require.NoError(t, err2)

	// Both calls should return the same key
	assert.Equal(t, keyID1, keyID2)
	assert.Equal(t, privKey1.D, privKey2.D, "Private key components should match")
}

func TestSignJWT_RS256Valid(t *testing.T) {
	kv := NewMockKVStore()
	keyID, privKey, _ := getOrCreateSigningKey(kv)

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
	kv := NewMockKVStore()
	keyID, privKey, _ := getOrCreateSigningKey(kv)

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
	kv := NewMockKVStore()

	// Create initial key
	_, _, _ = getOrCreateSigningKey(kv)
	storedPrivKey1, _ := kv.CmdGet("_system/priv/jwt-signing-key")
	storedPubKey1, _ := kv.CmdGet("_system/pub/jwt-signing-key")

	// Rotate
	err := rotateSigningKey(kv)
	require.NoError(t, err)

	// Verify new key exists at primary path
	storedPrivKey2, _ := kv.CmdGet("_system/priv/jwt-signing-key")
	assert.NotNil(t, storedPrivKey2)
	assert.NotEqual(t, storedPrivKey1, storedPrivKey2, "Private key should be different after rotation")

	// Verify previous private key saved at -prev path
	storedPrivKeyPrev, _ := kv.CmdGet("_system/priv/jwt-signing-key-prev")
	assert.Equal(t, storedPrivKey1, storedPrivKeyPrev, "Previous private key should be at _system/priv/jwt-signing-key-prev")

	// Verify previous public key saved at -prev path
	storedPubKeyPrev, _ := kv.CmdGet("_system/pub/jwt-signing-key-prev")
	assert.Equal(t, storedPubKey1, storedPubKeyPrev, "Previous public key should be at _system/pub/jwt-signing-key-prev")
}

func TestGetJWKS_ReturnsBothKeysDuringRotationOverlap(t *testing.T) {
	kv := NewMockKVStore()

	getOrCreateSigningKey(kv)
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
	kv := NewMockKVStore()

	getOrCreateSigningKey(kv)

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
	kv := NewMockKVStore()
	keyID, _, _ := getOrCreateSigningKey(kv)

	// SHA-256 thumbprint base64url-encoded = 43 chars (256 bits / 6 bits per char, no padding)
	assert.Equal(t, 43, len(keyID), "SHA-256 thumbprint should be 43 base64url chars")

	// Should only contain base64url characters (no +, /, or =)
	for _, ch := range keyID {
		assert.True(t, (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') || ch == '-' || ch == '_',
			"Key ID should be base64url encoded (no +, /, or = padding)")
	}
}

// __END_OF_FILE_MARKER__
