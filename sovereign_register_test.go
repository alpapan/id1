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

	body, _ := json.Marshal(RegisterBeginRequest{
		PublicKeyPEM: pubPEM,
		DeviceId:     "test-device-uuid",
		DeviceName:   "Edge on Windows",
	})
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

	// Pre-register a device key (simulates existing registration)
	CmdSet(KK(orcid, "pub", "keys", "existing-device"), map[string]string{"x-id": orcid}, []byte(pubPEM)).Exec()

	body, _ := json.Marshal(RegisterBeginRequest{
		PublicKeyPEM: pubPEM,
		DeviceId:     "new-device",
		DeviceName:   "Chrome on Linux",
	})
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

	// Pre-register a device key
	CmdSet(KK(orcid, "pub", "keys", "existing-device"), map[string]string{"x-id": orcid}, []byte(pubPEM)).Exec()

	// Sign a valid JWT for this ORCID
	tokenStr, err := signJWT(orcid, privKey, keyID)
	require.NoError(t, err)

	body, _ := json.Marshal(RegisterBeginRequest{
		PublicKeyPEM: pubPEM,
		DeviceId:     "new-device",
		DeviceName:   "Edge on Windows",
	})
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
	deviceId := "test-device-uuid"
	deviceName := "Edge on Windows"

	// Phase 1: begin
	body, _ := json.Marshal(RegisterBeginRequest{
		PublicKeyPEM: pubPEM,
		DeviceId:     deviceId,
		DeviceName:   deviceName,
	})
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
		DeviceId:          deviceId,
		DeviceName:        deviceName,
	})
	commitReq := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/commit?id="+orcid, bytes.NewReader(commitBody))
	commitReq.Header.Set("Content-Type", "application/json")
	commitRec := httptest.NewRecorder()
	HandleRegisterCommit(kv)(commitRec, commitReq)

	assert.Equal(t, http.StatusOK, commitRec.Code, "body: %s", commitRec.Body.String())

	// pub/keys/{deviceId} should exist
	data, err := CmdGet(KK(orcid, "pub", "keys", deviceId)).Exec()
	require.NoError(t, err)
	assert.Equal(t, pubPEM, string(data))

	// Device name should be stored
	nameData, err := CmdGet(KK(orcid, "pub", "keys", deviceId+".name")).Exec()
	require.NoError(t, err)
	assert.Equal(t, deviceName, string(nameData))

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
	body, _ := json.Marshal(RegisterBeginRequest{
		PublicKeyPEM: pubPEM,
		DeviceId:     "device-1",
		DeviceName:   "Test Browser",
	})
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
		DeviceId:          "device-1",
		DeviceName:        "Test Browser",
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
		DeviceId:          "device-1",
		DeviceName:        "Test Browser",
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
	deviceId := "test-device-uuid"

	// Phase 1
	body, _ := json.Marshal(RegisterBeginRequest{
		PublicKeyPEM: pubPEM,
		DeviceId:     deviceId,
		DeviceName:   "Test Browser",
	})
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
		DeviceId:          deviceId,
		DeviceName:        "Test Browser",
	})
	commitReq := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/commit?id="+orcid, bytes.NewReader(commitBody))
	commitReq.Header.Set("Content-Type", "application/json")
	commitRec := httptest.NewRecorder()
	HandleRegisterCommit(kv)(commitRec, commitReq)
	assert.Equal(t, http.StatusOK, commitRec.Code, "first commit")

	// Second commit (idempotent — pending gone, pub/keys/{deviceId} exists)
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
	deviceId := "test-device-uuid"

	// Phase 1: begin
	body, _ := json.Marshal(RegisterBeginRequest{
		PublicKeyPEM: pubPEM,
		DeviceId:     deviceId,
		DeviceName:   "Test Browser",
	})
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
		DeviceId:          deviceId,
		DeviceName:        "Test Browser",
	})
	commitReq := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/commit?id="+orcid, bytes.NewReader(commitBody))
	commitReq.Header.Set("Content-Type", "application/json")
	commitRec := httptest.NewRecorder()
	HandleRegisterCommit(kv)(commitRec, commitReq)
	require.Equal(t, http.StatusOK, commitRec.Code)

	// Verify TTL was set: the .ttl.{deviceId} file should exist in the pub/keys directory
	ttlPath := KK(orcid, "pub", "keys", ".ttl."+deviceId)
	ttlData, err := CmdGet(ttlPath).Exec()
	assert.NoError(t, err, "TTL metadata file should exist after commit")
	assert.NotEmpty(t, ttlData, "TTL metadata should contain the .after path")
}

// TestRegisterTwoDevicesSameUser verifies that a user can register keys from two
// different devices, each stored at its own pub/keys/{deviceId} path.
func TestRegisterTwoDevicesSameUser(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, signingKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)

	orcid := "0000-0001-2345-6789"

	// Register device 1 (new user — no JWT needed)
	privKey1, pubPEM1 := testGenerateRSAKeyPair(t)
	beginBody1, _ := json.Marshal(RegisterBeginRequest{
		PublicKeyPEM: pubPEM1,
		DeviceId:     "device-1",
		DeviceName:   "Edge on Windows",
	})
	req1 := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/begin?id="+orcid, bytes.NewReader(beginBody1))
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()
	HandleRegisterBegin(kv)(rec1, req1)
	require.Equal(t, http.StatusAccepted, rec1.Code)

	var beginResp1 RegisterBeginResponse
	json.Unmarshal(rec1.Body.Bytes(), &beginResp1)
	challengeBytes1, _ := base64.StdEncoding.DecodeString(beginResp1.Challenge)
	nonce1, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey1, challengeBytes1, nil)

	commitBody1, _ := json.Marshal(RegisterCommitRequest{
		RegistrationToken: beginResp1.RegistrationToken,
		Nonce:             base64.StdEncoding.EncodeToString(nonce1),
		DeviceId:          "device-1",
		DeviceName:        "Edge on Windows",
	})
	commitReq1 := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/commit?id="+orcid, bytes.NewReader(commitBody1))
	commitReq1.Header.Set("Content-Type", "application/json")
	commitRec1 := httptest.NewRecorder()
	HandleRegisterCommit(kv)(commitRec1, commitReq1)
	require.Equal(t, http.StatusOK, commitRec1.Code, "device-1 commit: %s", commitRec1.Body.String())

	// Register device 2 (user already has device-1, so JWT required)
	_, pubPEM2 := testGenerateRSAKeyPair(t)
	jwtToken, err := signJWT(orcid, signingKey, keyID)
	require.NoError(t, err)

	beginBody2, _ := json.Marshal(RegisterBeginRequest{
		PublicKeyPEM: pubPEM2,
		DeviceId:     "device-2",
		DeviceName:   "Safari on iPhone",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/begin?id="+orcid, bytes.NewReader(beginBody2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+jwtToken)
	rec2 := httptest.NewRecorder()
	HandleRegisterBegin(kv)(rec2, req2)
	require.Equal(t, http.StatusAccepted, rec2.Code, "device-2 begin with JWT: %s", rec2.Body.String())

	// Verify both device keys are stored independently
	data1, err := CmdGet(KK(orcid, "pub", "keys", "device-1")).Exec()
	require.NoError(t, err)
	assert.Equal(t, pubPEM1, string(data1))

	name1, err := CmdGet(KK(orcid, "pub", "keys", "device-1.name")).Exec()
	require.NoError(t, err)
	assert.Equal(t, "Edge on Windows", string(name1))
}
