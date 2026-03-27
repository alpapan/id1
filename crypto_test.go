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
	oldDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = oldDbpath })

	secret, err := generateSecret("test1")
	if err != nil {
		t.Fatalf("generateSecret failed: %s", err)
	}
	if len(secret) == 0 {
		t.Fatalf("generateSecret returned empty secret")
	}

	publicKey := `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3gMw5zAsvBuJ+swdVW8Ec9r1zu42Z+m7TsgoaV6yas58hxrPCeBUoNhFmz380yBpXjB7jwX1f5nGrZA9FWt2hmtJNLCvr6U1ZMZeERbPWjFIE02BWK0p+qZKByjpNv+LYMr8YM/JfYmqhhVbhqno15vVFyfNmaVIB6y1yJtn7xQIDAQAB
-----END PUBLIC KEY-----`

	data, err := encrypt(publicKey, secret)
	if err != nil {
		t.Errorf("encrypt failed: %v", err)
	}
	if len(data) == 0 {
		t.Errorf("encrypt returned empty data")
	}
}

func TestGenerateChallenge(t *testing.T) {
	oldDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = oldDbpath })

	challenge1, err1 := generateChallenge("testid1", testPubKey1)
	if err1 != nil {
		t.Fatalf("generateChallenge failed for testid1: %v", err1)
	}
	if len(challenge1) == 0 {
		t.Errorf("generateChallenge returned empty challenge for testid1")
	}

	challenge2, err2 := generateChallenge("testid2", testPubKey2)
	if err2 != nil {
		t.Fatalf("generateChallenge failed for testid2: %v", err2)
	}
	if len(challenge2) == 0 {
		t.Errorf("generateChallenge returned empty challenge for testid2")
	}

	// Challenges for different users with different keys must be different
	if challenge1 == challenge2 {
		t.Errorf("challenges for different users should differ: challenge1=%q, challenge2=%q", challenge1, challenge2)
	}
}

func TestGenerateChallengeWithInvalidPublicKey(t *testing.T) {
	oldDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = oldDbpath })

	_, err := generateChallenge("testid", "invalid-key")
	if err == nil {
		t.Errorf("expected error for invalid public key, got nil")
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
	t.Cleanup(func() { cryptoRandReader = oldReader })

	oldDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = oldDbpath })

	_, err := generateSecret("testid_rand_error")
	if err == nil {
		t.Errorf("expected error from rand.Read failure, got nil")
	}
	// Verify error message indicates the rand failure
	if err != nil && len(err.Error()) == 0 {
		t.Errorf("error message is empty")
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
	// Restore write permission so TempDir cleanup can succeed.
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
	})

	oldDbpath := dbpath
	dbpath = dir
	t.Cleanup(func() { dbpath = oldDbpath })

	_, err := generateSecret("testid_persist_error")
	if err == nil {
		t.Errorf("expected error from CmdSet failure, got nil")
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
