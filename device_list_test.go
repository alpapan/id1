package id1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleListDevices_ReturnsRegisteredDevices(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, signingKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)

	orcid := "0000-0001-2345-6789"

	// Register two devices
	CmdSet(KK(orcid, "pub", "keys", "device-1"), map[string]string{"x-id": orcid}, []byte("PEM-1")).Exec()
	CmdSet(KK(orcid, "pub", "keys", "device-1.name"), map[string]string{"x-id": orcid}, []byte("Edge on Windows")).Exec()
	CmdSet(KK(orcid, "pub", "keys", "device-2"), map[string]string{"x-id": orcid}, []byte("PEM-2")).Exec()
	CmdSet(KK(orcid, "pub", "keys", "device-2.name"), map[string]string{"x-id": orcid}, []byte("Safari on iPhone")).Exec()

	// Sign JWT for this user
	jwt, err := signJWT(orcid, signingKey, keyID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/sovereign/devices?id="+orcid, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	rec := httptest.NewRecorder()

	HandleListDevices(kv)(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp DeviceListResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(t, resp.Devices, 2)

	// Check device names (order may vary)
	names := map[string]string{}
	for _, d := range resp.Devices {
		names[d.DeviceId] = d.DeviceName
	}
	assert.Equal(t, "Edge on Windows", names["device-1"])
	assert.Equal(t, "Safari on iPhone", names["device-2"])
}

func TestHandleListDevices_RequiresJWT(t *testing.T) {
	kv := setupTestKVStore(t)
	GetOrCreateSigningKey(kv)

	req := httptest.NewRequest(http.MethodGet, "/auth/sovereign/devices?id=0000-0001-2345-6789", nil)
	rec := httptest.NewRecorder()

	HandleListDevices(kv)(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleListDevices_WrongUser(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, signingKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)

	// JWT is for a different user
	jwt, err := signJWT("0000-0002-0000-0001", signingKey, keyID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/sovereign/devices?id=0000-0001-2345-6789", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	rec := httptest.NewRecorder()

	HandleListDevices(kv)(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleDeleteDevice_RemovesDevice(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, signingKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)

	orcid := "0000-0001-2345-6789"

	// Register a device
	CmdSet(KK(orcid, "pub", "keys", "device-1"), map[string]string{"x-id": orcid}, []byte("PEM-1")).Exec()
	CmdSet(KK(orcid, "pub", "keys", "device-1.name"), map[string]string{"x-id": orcid}, []byte("Edge on Windows")).Exec()

	jwt, err := signJWT(orcid, signingKey, keyID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/auth/sovereign/devices?id="+orcid+"&device=device-1", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	rec := httptest.NewRecorder()

	HandleDeleteDevice(kv)(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Key should be gone
	_, err = CmdGet(KK(orcid, "pub", "keys", "device-1")).Exec()
	assert.Error(t, err, "device key should be deleted")

	// Name should be gone too
	_, err = CmdGet(KK(orcid, "pub", "keys", "device-1.name")).Exec()
	assert.Error(t, err, "device name should be deleted")
}

func TestHandleDeleteDevice_RequiresJWT(t *testing.T) {
	kv := setupTestKVStore(t)
	GetOrCreateSigningKey(kv)

	req := httptest.NewRequest(http.MethodDelete, "/auth/sovereign/devices?id=0000-0001-2345-6789&device=device-1", nil)
	rec := httptest.NewRecorder()

	HandleDeleteDevice(kv)(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
