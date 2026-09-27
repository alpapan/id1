// apps/backend/containers/id1/device_list_test.go
//
// group: auth
// tags: sovereign-keys, devices, testing
// summary: Tests for device enumeration and listing.
//
//

package id1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
	CmdSet(mustKK(t, orcid, "pub", "keys", "device-1"), map[string]string{"x-id": orcid}, []byte("PEM-1")).Exec()
	CmdSet(mustKK(t, orcid, "pub", "keys", "device-1.name"), map[string]string{"x-id": orcid}, []byte("Edge on Windows")).Exec()
	CmdSet(mustKK(t, orcid, "pub", "keys", "device-2"), map[string]string{"x-id": orcid}, []byte("PEM-2")).Exec()
	CmdSet(mustKK(t, orcid, "pub", "keys", "device-2.name"), map[string]string{"x-id": orcid}, []byte("Safari on iPhone")).Exec()

	// Sign JWT for this user
	jwt, err := signJWT(orcid, []string{"orcid"}, signingKey, keyID)
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
	jwt, err := signJWT("0000-0002-0000-0001", []string{"orcid"}, signingKey, keyID)
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
	CmdSet(mustKK(t, orcid, "pub", "keys", "device-1"), map[string]string{"x-id": orcid}, []byte("PEM-1")).Exec()
	CmdSet(mustKK(t, orcid, "pub", "keys", "device-1.name"), map[string]string{"x-id": orcid}, []byte("Edge on Windows")).Exec()

	jwt, err := signJWT(orcid, []string{"orcid"}, signingKey, keyID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/auth/sovereign/devices?id="+orcid+"&device=device-1", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	rec := httptest.NewRecorder()

	HandleDeleteDevice(kv)(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Key should be gone
	_, err = CmdGet(mustKK(t, orcid, "pub", "keys", "device-1")).Exec()
	assert.Error(t, err, "device key should be deleted")

	// Name should be gone too
	_, err = CmdGet(mustKK(t, orcid, "pub", "keys", "device-1.name")).Exec()
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

// hostileDeviceIdCases is the case list for
// TestHandleDeleteDeviceRejectsHostileDeviceId. These are the same
// illustrative bad-device SHAPES devicePattern's own boundary test uses
// (ingress_validation_test.go's badDevices: "../victim/pub/keys/x", "..",
// ".", "a/b", "", ".hidden"), not the identical values: the empty string is
// dropped because this handler already refuses it via its own "Missing id
// or device parameter" check before devicePattern is ever consulted; the
// bare "." case is dropped because it is already caught incidentally by
// K()'s exact-"."-segment rejection; and the traversal example's final
// segment is renamed from "x" to "evil" with no change in meaning. No
// production registry names this set, so the list is literal, and it is
// asserted below for exact length and membership.
//
// Of the four surviving cases, "../victim/pub/keys/evil" and ".." are also
// caught incidentally by K()'s exact-".."-segment rejection - they exercise
// devicePattern's guard the same way "." would have, but do not themselves
// require it. Only "a/b" and ".hidden" produce no "..", "." or "" segment
// and so are rejected exclusively by the new devicePattern check; they are
// what makes this table load-bearing for this task's fix.
var hostileDeviceIdCases = []string{
	"../victim/pub/keys/evil",
	"..",
	"a/b",
	".hidden",
}

// TestHandleDeleteDeviceHostileDeviceIdCaseListIsPopulated is the tripwire
// for the table below: dropping a case from hostileDeviceIdCases drops an
// assertion silently unless this also fails.
func TestHandleDeleteDeviceHostileDeviceIdCaseListIsPopulated(t *testing.T) {
	if len(hostileDeviceIdCases) != 4 {
		t.Fatalf("expected exactly 4 cases, got %d", len(hostileDeviceIdCases))
	}
	want := map[string]bool{
		"../victim/pub/keys/evil": true,
		"..":                      true,
		"a/b":                     true,
		".hidden":                 true,
	}
	for _, c := range hostileDeviceIdCases {
		if !want[c] {
			t.Errorf("hostileDeviceIdCases has unexpected case %q", c)
		}
	}
	for w := range want {
		found := false
		for _, c := range hostileDeviceIdCases {
			if c == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("hostileDeviceIdCases is missing case %q", w)
		}
	}
}

// TestHandleDeleteDeviceRejectsHostileDeviceId is the load-bearing test: the
// ?device= query parameter becomes a key segment at
// KK(orcidId, "pub", "keys", deviceId), and every value reaching that call
// must first satisfy devicePattern, the same character-class guard already
// applied to deviceId at every other public entry point in this plan
// (sovereign_register.go's HandleRegisterBegin/HandleRegisterCommit,
// sovereign_token.go's HandleSovereignToken, and id1.go's own ?device= path).
func TestHandleDeleteDeviceRejectsHostileDeviceId(t *testing.T) {
	for _, deviceId := range hostileDeviceIdCases {
		t.Run(deviceId, func(t *testing.T) {
			kv := setupTestKVStore(t)
			keyID, signingKey, err := GetOrCreateSigningKey(kv)
			require.NoError(t, err)

			orcid := "0000-0001-2345-6789"
			jwt, err := signJWT(orcid, []string{"orcid"}, signingKey, keyID)
			require.NoError(t, err)

			q := url.Values{}
			q.Set("id", orcid)
			q.Set("device", deviceId)
			req := httptest.NewRequest(http.MethodDelete, "/auth/sovereign/devices?"+q.Encode(), nil)
			req.Header.Set("Authorization", "Bearer "+jwt)
			rec := httptest.NewRecorder()

			HandleDeleteDevice(kv)(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
		})
	}
}

// TestHandleDeleteDeviceRejectsHostileDeviceIdBeforeAuth independently proves
// the devicePattern guard runs before JWT validation, rather than merely
// before KK(): it pairs a hostile deviceId with NO Authorization header at
// all. If the guard ran after JWT validation, this request would be
// rejected 401 (missing auth) before devicePattern is ever consulted; the
// observed 400 instead shows the guard runs first, exactly as
// device_list.go's source order requires.
func TestHandleDeleteDeviceRejectsHostileDeviceIdBeforeAuth(t *testing.T) {
	kv := setupTestKVStore(t)
	GetOrCreateSigningKey(kv)

	orcid := "0000-0001-2345-6789"

	q := url.Values{}
	q.Set("id", orcid)
	q.Set("device", "a/b")
	req := httptest.NewRequest(http.MethodDelete, "/auth/sovereign/devices?"+q.Encode(), nil)
	// Deliberately no Authorization header.
	rec := httptest.NewRecorder()

	HandleDeleteDevice(kv)(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
}

// TestHandleListDevicesRefusesSymlinkedKeysDir verifies that HandleListDevices
// does not follow a symlink planted at {orcidId}/pub/keys. Today's os.ReadDir
// call follows any symlinked directory and would surface a device name that
// lives entirely outside the KV store.
func TestHandleListDevicesRefusesSymlinkedKeysDir(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, signingKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)

	orcid := "0000-0001-2345-6789"

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "rogue-device"), []byte("OUTSIDE-DEVICE-PEM"), 0644); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	orcidPubDir := filepath.Join(dbpath, orcid, "pub")
	if err := os.MkdirAll(orcidPubDir, 0770); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(orcidPubDir, "keys")); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	jwt, err := signJWT(orcid, []string{"orcid"}, signingKey, keyID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/sovereign/devices?id="+orcid, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	rec := httptest.NewRecorder()

	HandleListDevices(kv)(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp DeviceListResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	if len(resp.Devices) != 0 {
		t.Error("listing must not follow a symlinked pub/keys directory and must not surface a device name from outside the store")
	}
}

// TestHandleListDevicesRefusesInStoreRelativeSymlinkedKeysDir verifies that
// HandleListDevices does not follow an in-store RELATIVE symlink planted at
// {attackerId}/pub/keys whose target stays inside the store but names a
// different identity's namespace (attacker/pub/keys -> ../../victim/pub/keys).
// os.Root only refuses an absolute symlink or one that leaves the store; this
// relative, in-store shape is exactly what pathIsSymlinkFree closes. Without
// it, readDeviceKeysDir would list victim's real device file, and its name
// reaches the JSON response directly from entry.Name() with no further
// per-entry guard - so the attacker would see victim's device id under their
// own identity.
func TestHandleListDevicesRefusesInStoreRelativeSymlinkedKeysDir(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, signingKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)

	victim := "0000-0001-1111-1111"
	attacker := "0000-0002-2222-2222"

	victimKeysDir := filepath.Join(dbpath, victim, "pub", "keys")
	if err := os.MkdirAll(victimKeysDir, 0770); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(victimKeysDir, "device-1"), []byte("VICTIM-DEVICE-PEM"), 0644); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	attackerPubDir := filepath.Join(dbpath, attacker, "pub")
	if err := os.MkdirAll(attackerPubDir, 0770); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	if err := os.Symlink(filepath.Join("..", "..", victim, "pub", "keys"), filepath.Join(attackerPubDir, "keys")); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	jwt, err := signJWT(attacker, []string{"orcid"}, signingKey, keyID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/sovereign/devices?id="+attacker, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	rec := httptest.NewRecorder()

	HandleListDevices(kv)(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp DeviceListResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	if len(resp.Devices) != 0 {
		t.Error("listing must not follow an in-store relative symlinked pub/keys directory and must not surface victim's device id under the attacker's identity")
	}
}
