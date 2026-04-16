package id1

import (
	"testing"
)

func setupAuthTest(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })
}

func TestAuthOwnerCanSetOwnPublicKey(t *testing.T) {
	setupAuthTest(t)
	// Multi-device: keys at pub/keys/{deviceId}
	testid1DeviceKey := KK("testid1", "pub", "keys", "device-1")
	CmdSet(testid1DeviceKey, map[string]string{"x-id": "testid1"}, []byte("..........")).Exec()

	if !auth("testid1", NewCommand(Set, testid1DeviceKey, map[string]string{}, []byte{})) {
		t.Errorf("testid1 should be authorized to set own device key")
	}
}

func TestAuthNonOwnerCannotSetOthersKey(t *testing.T) {
	setupAuthTest(t)
	testid1DeviceKey := KK("testid1", "pub", "keys", "device-1")
	CmdSet(testid1DeviceKey, map[string]string{"x-id": "testid1"}, []byte("..........")).Exec()

	if auth("testid2", NewCommand(Set, testid1DeviceKey, map[string]string{}, []byte{})) {
		t.Errorf("testid2 should not be authorized to modify testid1's device key")
	}
}

func TestAuthAnonymousCanReadPublicKeys(t *testing.T) {
	setupAuthTest(t)
	testid1DeviceKey := KK("testid1", "pub", "keys", "device-1")
	CmdSet(testid1DeviceKey, map[string]string{"x-id": "testid1"}, []byte("..........")).Exec()

	if !auth("", NewCommand(Get, testid1DeviceKey, map[string]string{}, []byte{})) {
		t.Errorf("anonymous user should be authorized to read public device keys")
	}
}

func TestParseClaims(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0aWQiLCJpYXQiOjE1MTYyMzkwMjJ9.m7GbsjZeOBZhdFfaU1_ulqeaogLi5gduLXqfLhyxH5w"

	if claims, err := validateToken(token, "test"); err != nil {
		t.Errorf("err: %s", err)
	} else if claims.Subject != "testid" {
		t.Errorf("expected 'testid' got %s", claims.Subject)
	}
}

func TestIdExists(t *testing.T) {
	setupAuthTest(t)
	// Multi-device: keys live at pub/keys/{deviceId}
	deviceKey := KK("testid1", "pub", "keys", "default")
	if _, err := CmdSet(deviceKey, map[string]string{"x-id": "testid1"}, []byte("..........")).Exec(); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	if !idExists("testid1") {
		t.Errorf("idExists should return true for testid1 after setting a device key")
	}

	if idExists("testid123") {
		t.Errorf("idExists should return false for non-existent testid123")
	}
}

func TestIdExistsMultiDevice(t *testing.T) {
	setupAuthTest(t)

	orcid := "0000-0001-2345-6789"

	// No keys registered — should be false
	if idExists(orcid) {
		t.Errorf("idExists should return false when no keys exist")
	}

	// Register a device key at pub/keys/device-1
	CmdSet(KK(orcid, "pub", "keys", "device-1"), map[string]string{"x-id": orcid}, []byte("PEM-DATA")).Exec()
	if !idExists(orcid) {
		t.Errorf("idExists should return true when a device key exists at pub/keys/device-1")
	}

	// Register a second device — still true
	CmdSet(KK(orcid, "pub", "keys", "device-2"), map[string]string{"x-id": orcid}, []byte("PEM-DATA-2")).Exec()
	if !idExists(orcid) {
		t.Errorf("idExists should return true with multiple device keys")
	}

	// Metadata-only (.name files) should not count
	setupAuthTest(t)
	orcid2 := "0000-0002-0000-0001"
	CmdSet(KK(orcid2, "pub", "keys", "device-1.name"), map[string]string{"x-id": orcid2}, []byte("My Browser")).Exec()
	if idExists(orcid2) {
		t.Errorf("idExists should return false when only .name metadata files exist")
	}
}

var testPubKey1 = `-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAM1W6T4DqjOTFHvsAUTebVF+NofSA3qJW7SF7gJTPh3IE0W6hkT0XSMP
Ue6eyS+2vITfmX5gShkm7z/HHpUS2Kho+Rj8HjRu0Ng68qbdpCkYcgkrrEJneX7U
WqmD6zw8RKkLA4Rsfu+wrTjf0ijxpS2vS0fzghyB9TcbsFzCo573AgMBAAE=
-----END RSA PUBLIC KEY-----`

var testPubKey2 = `-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANDSsusgXGowG2Dsm2pCWyGbIEEGwsRgoKbUPx2JuVI0NWEvTrEmPfqa
H23ACLwetp4XMgZEYLmuS3PkA/HuQiUkYPElKEmfuO2jQ6F4/mHy6UkOsP9PMXwl
ff02vCJ43hBFIJdgchDSywHIb4F1hv6ap6PlrYMGwvIJ6gln9GIdAgMBAAE=
-----END RSA PUBLIC KEY-----`
