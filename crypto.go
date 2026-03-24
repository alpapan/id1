package id1

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"time"
)

// cryptoRandReader is the source of cryptographic randomness.
// It is a package-level variable so tests can substitute a failing reader
// to verify error propagation without touching crypto/rand itself.
var cryptoRandReader io.Reader = rand.Reader

func encrypt(publicKeyPEM string, data string) ([]byte, error) {
	result := []byte{}

	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return result, fmt.Errorf("invalid key")
	}

	var publicKey *rsa.PublicKey
	if pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		publicKey = pubKey
	} else if pubKey, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return result, fmt.Errorf("only RSA keys supported")
		}
		publicKey = rsaKey
	} else {
		return result, fmt.Errorf("error parsing key")
	}

	return rsa.EncryptOAEP(sha256.New(), cryptoRandReader, publicKey, []byte(data), nil)
}

func generateChallenge(id, publicKey string) (string, error) {
	secret, err := generateSecret(id)
	if err != nil {
		return "", err
	}
	encryptedSecret, err := encrypt(publicKey, secret)
	if err != nil {
		return "", err
	}
	challenge := base64.StdEncoding.EncodeToString(encryptedSecret)
	return challenge, nil
}

// generateSecretWithSalt derives a deterministic secret from id, salt, and the current UTC day
// using HMAC-SHA256 to prevent length-extension attacks.
//
// NOTE: days since epoch makes secrets rotate at midnight UTC each day.
// This is an intentional design decision: sessions crossing midnight must
// re-authenticate. Any callers that cache the secret must account for this.
func generateSecretWithSalt(id, salt string) string {
	t := time.Now().UTC()
	daysSinceEpoch := t.Unix() / 86400
	message := fmt.Sprintf("id1:%s:day:%d", id, daysSinceEpoch)
	h := hmac.New(sha256.New, []byte(salt))
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// generateSecret retrieves or creates a persistent random salt for id, then
// derives the daily-rotating HMAC secret. Returns an error if the random salt
// cannot be generated or persisted; callers must propagate the error and must
// not fall back to a zero-byte salt (which would make all affected users share
// identical secrets — a critical security vulnerability).
func generateSecret(id string) (string, error) {
	saltKey := KK(id, "priv", "salt")
	saltBytes, err := CmdGet(saltKey).Exec()
	if err != nil || len(saltBytes) == 0 {
		saltBytes = make([]byte, 32)
		// CRITICAL: a rand read failure must not fall back to zero bytes.
		// Zero salt means all affected users share identical secrets.
		if _, err := io.ReadFull(cryptoRandReader, saltBytes); err != nil {
			return "", fmt.Errorf("crypto/rand failed generating salt for %s: %w", id, err)
		}
		if _, err := CmdSet(saltKey, map[string]string{"x-id": id}, saltBytes).Exec(); err != nil {
			return "", fmt.Errorf("failed to persist salt for %s: %w", id, err)
		}
	}
	return generateSecretWithSalt(id, hex.EncodeToString(saltBytes)), nil
}

// __END_OF_FILE_MARKER__
