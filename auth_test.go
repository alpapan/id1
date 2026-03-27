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
	testid1PubKey := K("testid1/pub/key")
	if _, err := NewCommand(Set, K("testid1/pub/key"), map[string]string{}, []byte("..........")).Exec(); err != nil {
		t.Fatalf("setup failed to set initial key: %v", err)
	}

	if !auth("testid1", NewCommand(Set, testid1PubKey, map[string]string{}, []byte{})) {
		t.Errorf("testid1 should be authorized to set own public key")
	}
}

func TestAuthNonOwnerCannotSetOthersKey(t *testing.T) {
	setupAuthTest(t)
	testid1PubKey := K("testid1/pub/key")
	if _, err := NewCommand(Set, K("testid1/pub/key"), map[string]string{}, []byte("..........")).Exec(); err != nil {
		t.Fatalf("setup failed to set initial key: %v", err)
	}

	if auth("testid2", NewCommand(Set, testid1PubKey, map[string]string{}, []byte{})) {
		t.Errorf("testid2 should not be authorized to modify testid1's public key")
	}
}

func TestAuthAnonymousCanReadPublicKeys(t *testing.T) {
	setupAuthTest(t)
	testid1PubKey := K("testid1/pub/key")
	if _, err := NewCommand(Set, K("testid1/pub/key"), map[string]string{}, []byte("..........")).Exec(); err != nil {
		t.Fatalf("setup failed to set initial key: %v", err)
	}

	if !auth("", NewCommand(Get, testid1PubKey, map[string]string{}, []byte{})) {
		t.Errorf("anonymous user should be authorized to read public keys")
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
	testidPubKey := K("testid1/pub/key")
	if _, err := NewCommand(Set, testidPubKey, map[string]string{}, []byte("..........")).Exec(); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	if !idExists("testid1") {
		t.Errorf("idExists should return true for testid1 after setting its public key")
	}

	if idExists("testid123") {
		t.Errorf("idExists should return false for non-existent testid123")
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
