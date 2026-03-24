package id1

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
)

// errReader always returns an error, used to simulate crypto/rand failures.
type errReader struct{}

func (e *errReader) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("simulated rand.Read failure")
}

func TestPublicKeyEnc(t *testing.T) {
	dbpath = t.TempDir()
	secret, err := generateSecret("test1")
	if err != nil {
		t.Fatalf("generateSecret failed: %s", err)
	}
	if data, err := encrypt(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3gMw5zAsvBuJ+swdVW8Ec9r1zu42Z+m7TsgoaV6yas58hxrPCeBUoNhFmz380yBpXjB7jwX1f5nGrZA9FWt2hmtJNLCvr6U1ZMZeERbPWjFIE02BWK0p+qZKByjpNv+LYMr8YM/JfYmqhhVbhqno15vVFyfNmaVIB6y1yJtn7xQIDAQAB
-----END PUBLIC KEY-----`, secret); err != nil || len(data) == 0 {
		t.Errorf("encrypt failed: %s", err)
	}
}

func TestGenerateChallenge(t *testing.T) {
	dbpath = t.TempDir()
	challenge1, err1 := generateChallenge("testid1", testPubKey1)
	challenge2, err2 := generateChallenge("testid2", testPubKey2)
	if err1 != nil || err2 != nil {
		t.Errorf("error generating challenge: %v %v", err1, err2)
	}
	if challenge1 == challenge2 {
		t.Errorf("invalid challenge")
	}
}

// TestGenerateSecretWithSalt verifies that different salts produce different secrets.
func TestGenerateSecretWithSalt(t *testing.T) {
	s1 := generateSecretWithSalt("user1", "salt_aaaa")
	s2 := generateSecretWithSalt("user1", "salt_bbbb")
	if s1 == s2 {
		t.Error("expected different secrets for different salts, got same")
	}
	if s1 == "" || s2 == "" {
		t.Error("generateSecretWithSalt returned empty string")
	}
}

// TestGenerateSecretSameSalt verifies deterministic output for same inputs.
func TestGenerateSecretSameSalt(t *testing.T) {
	s1 := generateSecretWithSalt("userX", "same_salt")
	s2 := generateSecretWithSalt("userX", "same_salt")
	if s1 != s2 {
		t.Error("expected identical secrets for same inputs, got different")
	}
}

// TestGenerateSecretRandReadError verifies that a rand.Read failure causes
// generateSecret to return a non-nil error rather than silently falling back
// to a zero-byte salt (which would make all users share identical secrets).
func TestGenerateSecretRandReadError(t *testing.T) {
	oldReader := cryptoRandReader
	cryptoRandReader = &errReader{}
	defer func() { cryptoRandReader = oldReader }()

	oldDbpath := dbpath
	dbpath = t.TempDir()
	defer func() { dbpath = oldDbpath }()

	_, err := generateSecret("testid_rand_error")
	if err == nil {
		t.Error("expected error from rand.Read failure, got nil")
	}
}

// TestGenerateSecretSaltPersistError verifies that a CmdSet failure causes
// generateSecret to return a non-nil error.
func TestGenerateSecretSaltPersistError(t *testing.T) {
	dir := t.TempDir()
	// Make the temp dir read-only so os.MkdirAll inside set() fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skip("cannot set directory to read-only; skipping")
	}
	defer func() {
		// Restore write permission so TempDir cleanup can succeed.
		_ = os.Chmod(dir, 0o700)
	}()

	oldDbpath := dbpath
	dbpath = dir
	defer func() { dbpath = oldDbpath }()

	_, err := generateSecret("testid_persist_error")
	if err == nil {
		t.Error("expected error from CmdSet failure, got nil")
	}
}

// TestOAEPEncryptionRoundtrip verifies that encrypt() uses OAEP SHA-256 by
// decrypting the ciphertext with rsa.DecryptOAEP and comparing with the
// original plaintext.
func TestOAEPEncryptionRoundtrip(t *testing.T) {
	// Generate a fresh 2048-bit RSA key pair.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Encode public key as PKIX PEM (BEGIN PUBLIC KEY).
	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}))

	plaintext := "oaep-roundtrip-test-secret"
	ciphertext, err := encrypt(pubPEM, plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Decrypt with OAEP SHA-256 to confirm the ciphertext scheme.
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		t.Fatalf("DecryptOAEP failed: %v", err)
	}
	if string(decrypted) != plaintext {
		t.Errorf("roundtrip mismatch: got %q, want %q", string(decrypted), plaintext)
	}
}

// __END_OF_FILE_MARKER__
