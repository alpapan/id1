package id1

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testGenerateRSAKeyPair generates an RSA-2048 key pair and returns the
// private key plus a PEM-encoded public key string.
func testGenerateRSAKeyPair(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	return privKey, string(pemBlock)
}

func TestRegisterBeginNewUser(t *testing.T) {
	kv := setupTestKVStore(t)
	// Need signing key for handler init (even if not used for new-user path)
	GetOrCreateSigningKey(kv)

	_, pubPEM := testGenerateRSAKeyPair(t)

	body, _ := json.Marshal(RegisterBeginRequest{PublicKeyPEM: pubPEM})
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/begin?id=0000-0001-2345-6789", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	HandleRegisterBegin(kv)(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code, "response body: %s", rec.Body.String())

	var resp RegisterBeginResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.RegistrationToken)
	assert.NotEmpty(t, resp.Challenge)
	assert.Equal(t, 3600, resp.ExpiresIn)
}

func TestRegisterBeginExistingUserNoJWT(t *testing.T) {
	kv := setupTestKVStore(t)
	GetOrCreateSigningKey(kv)

	_, pubPEM := testGenerateRSAKeyPair(t)
	orcid := "0000-0001-2345-6789"

	// Pre-register a key (simulates the orphaned key scenario)
	CmdSet(KK(orcid, "pub", "key"), map[string]string{"x-id": orcid}, []byte(pubPEM)).Exec()

	body, _ := json.Marshal(RegisterBeginRequest{PublicKeyPEM: pubPEM})
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/begin?id="+orcid, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	HandleRegisterBegin(kv)(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestRegisterBeginExistingUserWithJWT(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, privKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)

	_, pubPEM := testGenerateRSAKeyPair(t)
	orcid := "0000-0001-2345-6789"

	// Pre-register a key
	CmdSet(KK(orcid, "pub", "key"), map[string]string{"x-id": orcid}, []byte(pubPEM)).Exec()

	// Sign a valid JWT for this ORCID
	tokenStr, err := signJWT(orcid, privKey, keyID)
	require.NoError(t, err)

	body, _ := json.Marshal(RegisterBeginRequest{PublicKeyPEM: pubPEM})
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/begin?id="+orcid, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	HandleRegisterBegin(kv)(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code, "re-registration with JWT should succeed: %s", rec.Body.String())
}

func TestRegisterCommitSuccess(t *testing.T) {
	kv := setupTestKVStore(t)
	GetOrCreateSigningKey(kv)

	privKey, pubPEM := testGenerateRSAKeyPair(t)
	orcid := "0000-0001-2345-6789"

	// Phase 1: begin
	body, _ := json.Marshal(RegisterBeginRequest{PublicKeyPEM: pubPEM})
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/begin?id="+orcid, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	HandleRegisterBegin(kv)(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	var beginResp RegisterBeginResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &beginResp))

	// Decrypt challenge to prove possession
	challengeBytes, err := base64.StdEncoding.DecodeString(beginResp.Challenge)
	require.NoError(t, err)
	nonce, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, challengeBytes, nil)
	require.NoError(t, err)

	// Phase 2: commit
	commitBody, _ := json.Marshal(RegisterCommitRequest{
		RegistrationToken: beginResp.RegistrationToken,
		Nonce:             base64.StdEncoding.EncodeToString(nonce),
	})
	commitReq := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/commit?id="+orcid, bytes.NewReader(commitBody))
	commitReq.Header.Set("Content-Type", "application/json")
	commitRec := httptest.NewRecorder()
	HandleRegisterCommit(kv)(commitRec, commitReq)

	assert.Equal(t, http.StatusOK, commitRec.Code, "body: %s", commitRec.Body.String())

	// pub/key should exist
	data, err := CmdGet(KK(orcid, "pub", "key")).Exec()
	require.NoError(t, err)
	assert.Equal(t, pubPEM, string(data))

	// pending should be cleaned up
	_, err = CmdGet(KK(orcid, "priv", "pending", beginResp.RegistrationToken+".key")).Exec()
	assert.Error(t, err, "pending key should be deleted after commit")
}

func TestRegisterCommitWrongNonce(t *testing.T) {
	kv := setupTestKVStore(t)
	GetOrCreateSigningKey(kv)

	_, pubPEM := testGenerateRSAKeyPair(t)
	orcid := "0000-0001-2345-6789"

	// Phase 1
	body, _ := json.Marshal(RegisterBeginRequest{PublicKeyPEM: pubPEM})
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/begin?id="+orcid, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	HandleRegisterBegin(kv)(rec, req)

	var beginResp RegisterBeginResponse
	json.Unmarshal(rec.Body.Bytes(), &beginResp)

	// Phase 2: wrong nonce
	commitBody, _ := json.Marshal(RegisterCommitRequest{
		RegistrationToken: beginResp.RegistrationToken,
		Nonce:             base64.StdEncoding.EncodeToString([]byte("wrong-nonce-value")),
	})
	commitReq := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/commit?id="+orcid, bytes.NewReader(commitBody))
	commitReq.Header.Set("Content-Type", "application/json")
	commitRec := httptest.NewRecorder()
	HandleRegisterCommit(kv)(commitRec, commitReq)

	assert.Equal(t, http.StatusUnauthorized, commitRec.Code)
}

func TestRegisterCommitExpiredToken(t *testing.T) {
	kv := setupTestKVStore(t)
	GetOrCreateSigningKey(kv)

	orcid := "0000-0001-2345-6789"

	// Commit with token that was never created
	commitBody, _ := json.Marshal(RegisterCommitRequest{
		RegistrationToken: "nonexistent-token",
		Nonce:             base64.StdEncoding.EncodeToString([]byte("anything")),
	})
	commitReq := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/commit?id="+orcid, bytes.NewReader(commitBody))
	commitReq.Header.Set("Content-Type", "application/json")
	commitRec := httptest.NewRecorder()
	HandleRegisterCommit(kv)(commitRec, commitReq)

	assert.Equal(t, http.StatusBadRequest, commitRec.Code)
}

func TestRegisterCommitIdempotent(t *testing.T) {
	kv := setupTestKVStore(t)
	GetOrCreateSigningKey(kv)

	privKey, pubPEM := testGenerateRSAKeyPair(t)
	orcid := "0000-0001-2345-6789"

	// Phase 1
	body, _ := json.Marshal(RegisterBeginRequest{PublicKeyPEM: pubPEM})
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/begin?id="+orcid, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	HandleRegisterBegin(kv)(rec, req)

	var beginResp RegisterBeginResponse
	json.Unmarshal(rec.Body.Bytes(), &beginResp)

	challengeBytes, _ := base64.StdEncoding.DecodeString(beginResp.Challenge)
	nonce, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, challengeBytes, nil)
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)

	// First commit
	commitBody, _ := json.Marshal(RegisterCommitRequest{
		RegistrationToken: beginResp.RegistrationToken,
		Nonce:             nonceB64,
	})
	commitReq := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/commit?id="+orcid, bytes.NewReader(commitBody))
	commitReq.Header.Set("Content-Type", "application/json")
	commitRec := httptest.NewRecorder()
	HandleRegisterCommit(kv)(commitRec, commitReq)
	assert.Equal(t, http.StatusOK, commitRec.Code, "first commit")

	// Second commit (idempotent — pending gone, pub/key exists)
	commitReq2 := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/commit?id="+orcid, bytes.NewReader(commitBody))
	commitReq2.Header.Set("Content-Type", "application/json")
	commitRec2 := httptest.NewRecorder()
	HandleRegisterCommit(kv)(commitRec2, commitReq2)
	assert.Equal(t, http.StatusOK, commitRec2.Code, "idempotent retry should return 200")
}

func TestRegisterCommitSetsTTL(t *testing.T) {
	kv := setupTestKVStore(t)
	GetOrCreateSigningKey(kv)

	privKey, pubPEM := testGenerateRSAKeyPair(t)
	orcid := "0000-0001-2345-6789"

	// Phase 1: begin
	body, _ := json.Marshal(RegisterBeginRequest{PublicKeyPEM: pubPEM})
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/begin?id="+orcid, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	HandleRegisterBegin(kv)(rec, req)

	var beginResp RegisterBeginResponse
	json.Unmarshal(rec.Body.Bytes(), &beginResp)

	challengeBytes, _ := base64.StdEncoding.DecodeString(beginResp.Challenge)
	nonce, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, challengeBytes, nil)

	// Phase 2: commit
	commitBody, _ := json.Marshal(RegisterCommitRequest{
		RegistrationToken: beginResp.RegistrationToken,
		Nonce:             base64.StdEncoding.EncodeToString(nonce),
	})
	commitReq := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/commit?id="+orcid, bytes.NewReader(commitBody))
	commitReq.Header.Set("Content-Type", "application/json")
	commitRec := httptest.NewRecorder()
	HandleRegisterCommit(kv)(commitRec, commitReq)
	require.Equal(t, http.StatusOK, commitRec.Code)

	// Verify TTL was set: the .ttl.key file should exist in the pub directory
	ttlPath := KK(orcid, "pub", ".ttl.key")
	ttlData, err := CmdGet(ttlPath).Exec()
	assert.NoError(t, err, "TTL metadata file should exist after commit")
	assert.NotEmpty(t, ttlData, "TTL metadata should contain the .after path")
}
