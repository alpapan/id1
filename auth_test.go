// apps/backend/containers/id1/auth_test.go
//
// group: auth
// tags: authentication, authorization, testing
// summary: Tests for authorization logic and permission checking.
//
//

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

	if !auth("testid1", NewCommand(Set, testid1DeviceKey, map[string]string{}, []byte{}), "") {
		t.Errorf("testid1 should be authorized to set own device key")
	}
}

func TestAuthNonOwnerCannotSetOthersKey(t *testing.T) {
	setupAuthTest(t)
	testid1DeviceKey := KK("testid1", "pub", "keys", "device-1")
	CmdSet(testid1DeviceKey, map[string]string{"x-id": "testid1"}, []byte("..........")).Exec()

	if auth("testid2", NewCommand(Set, testid1DeviceKey, map[string]string{}, []byte{}), "") {
		t.Errorf("testid2 should not be authorized to modify testid1's device key")
	}
}

func TestAuthAnonymousCanReadPublicKeys(t *testing.T) {
	setupAuthTest(t)
	testid1DeviceKey := KK("testid1", "pub", "keys", "device-1")
	CmdSet(testid1DeviceKey, map[string]string{"x-id": "testid1"}, []byte("..........")).Exec()

	if !auth("", NewCommand(Get, testid1DeviceKey, map[string]string{}, []byte{}), "") {
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

	// No keys registered - should be false
	if idExists(orcid) {
		t.Errorf("idExists should return false when no keys exist")
	}

	// Register a device key at pub/keys/device-1
	CmdSet(KK(orcid, "pub", "keys", "device-1"), map[string]string{"x-id": orcid}, []byte("PEM-DATA")).Exec()
	if !idExists(orcid) {
		t.Errorf("idExists should return true when a device key exists at pub/keys/device-1")
	}

	// Register a second device - still true
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

// TestIdExists_SingularPubKey verifies that idExists returns true when only
// the singular {id}/pub/key file is populated. This closes an anonymous
// overwrite gap that would otherwise let an attacker forge service JWTs once
// HandleSovereignToken starts falling back to the singular path.
func TestIdExists_SingularPubKey(t *testing.T) {
	setupAuthTest(t)

	if idExists("service") {
		t.Fatal("precondition failed: service must not exist yet")
	}

	// Write only at the singular path, not under pub/keys/.
	singularKey := KK("service", "pub", "key")
	if _, err := CmdSet(singularKey, map[string]string{"x-id": "service"}, []byte(testPubKey1)).Exec(); err != nil {
		t.Fatal(err)
	}

	if !idExists("service") {
		t.Error("idExists should return true when only {id}/pub/key is populated")
	}
}

// TestAuth_AnonymousOverwriteBlockedAfterSingularBootstrap verifies that once
// a service identity has bootstrapped at {id}/pub/key, a second POST to the
// same path is rejected even with the correct internal secret - preventing an
// attacker (or a misconfigured caller) from overwriting the service key and
// minting forged JWTs. This gate adds no in-band recovery/overwrite path.
func TestAuth_AnonymousOverwriteBlockedAfterSingularBootstrap(t *testing.T) {
	setupAuthTest(t)
	t.Setenv("ID1_INTERNAL_SECRET", "test-internal-secret")

	singularKey := KK("service", "pub", "key")

	// Seed the singular key to simulate a successful prior bootstrap.
	if _, err := CmdSet(singularKey, map[string]string{"x-id": "service"}, []byte(testPubKey1)).Exec(); err != nil {
		t.Fatal(err)
	}

	// A second POST, even with the correct internal secret, must be rejected:
	// the identity already exists.
	if auth("", NewCommand(Set, singularKey, map[string]string{}, []byte{}), "test-internal-secret") {
		t.Error("anonymous overwrite should be rejected once service identity exists, even with the internal secret")
	}
}

// TestAuth_NewIdBootstrapRequiresInternalSecret verifies that the anonymous
// new-id bootstrap (Set to {id}/pub/key for an id that does not yet exist) is
// gated on the ID1_INTERNAL_SECRET header: no secret configured, no header, or
// a wrong header must all be rejected; only the correct header is authorized.
// Closes an unauthenticated identity-squat: without this gate any caller could
// permanently claim an unclaimed id string with no validation, no TTL, and no
// in-band recovery.
func TestAuth_NewIdBootstrapRequiresInternalSecret(t *testing.T) {
	setupAuthTest(t)
	t.Setenv("ID1_INTERNAL_SECRET", "test-internal-secret")

	singularKey := KK("service", "pub", "key")
	newCmd := func() Command { return NewCommand(Set, singularKey, map[string]string{}, []byte{}) }

	if auth("", newCmd(), "") {
		t.Error("bootstrap without the internal secret header should be rejected")
	}
	if auth("", newCmd(), "wrong-secret") {
		t.Error("bootstrap with an incorrect internal secret should be rejected")
	}
	if !auth("", newCmd(), "test-internal-secret") {
		t.Error("bootstrap with the correct internal secret should be authorized when the id does not exist")
	}
}

// TestAuth_NewIdBootstrapFailsClosedWhenSecretUnset verifies that an unset
// (or empty) ID1_INTERNAL_SECRET never authorizes the bootstrap, even against
// an empty header - the gate fails closed on misconfiguration rather than
// silently degrading to the old anonymous-allow behaviour.
func TestAuth_NewIdBootstrapFailsClosedWhenSecretUnset(t *testing.T) {
	setupAuthTest(t)
	t.Setenv("ID1_INTERNAL_SECRET", "")

	singularKey := KK("service", "pub", "key")
	if auth("", NewCommand(Set, singularKey, map[string]string{}, []byte{}), "") {
		t.Error("bootstrap must be rejected when ID1_INTERNAL_SECRET is unset")
	}
}
