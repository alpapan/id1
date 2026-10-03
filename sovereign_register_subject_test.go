// group: auth
// tags: sovereign-keys, registration, subject-gate, security
// summary: The public two-phase device registration path accepts only an ORCID-shaped
// subject. Machine and reserved identities never register a device key through it.

package id1

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nonPersonSubjects are ids the public registration path must refuse. Each is a
// subject a caller can hold a valid RS256 JWT for (a machine mint, or a crafted id)
// while not being a person's ORCID iD. The list is a literal tripwire: there is no
// production registry of reserved subjects to derive it from.
var nonPersonSubjects = map[string]string{
	"service":            "service",
	"admin":              "admin",
	"system-namespace":   "_system",
	"authstate-prefix":   "_authstate",
	"orcid-too-short":    "0000-0001-2345-678",
	"orcid-lowercase-x":  "0000-0001-2345-678x",
	"orcid-trailing-nl":  "0000-0001-2345-6789\n",
	"orcid-with-suffix":  "0000-0001-2345-6789-service",
	"orcid-with-dotdots": "0000-0001-2345-6789/../service",
}

func TestNonPersonSubjectCaseList(t *testing.T) {
	assert.Len(t, nonPersonSubjects, 9)
	for _, name := range []string{"service", "admin", "system-namespace", "authstate-prefix", "orcid-too-short", "orcid-lowercase-x", "orcid-trailing-nl", "orcid-with-suffix", "orcid-with-dotdots"} {
		assert.Contains(t, nonPersonSubjects, name)
	}
}

func TestRegisterBegin_NonPersonSubject_Refused(t *testing.T) {
	for name, subject := range nonPersonSubjects {
		t.Run(name, func(t *testing.T) {
			kv := setupTestKVStore(t)
			keyID, signingKey, err := GetOrCreateSigningKey(kv)
			require.NoError(t, err)
			_, pubPEM := testGenerateRSAKeyPair(t)
			// A valid RS256 JWT whose subject equals ?id: the only gate left to refuse is
			// the subject shape itself.
			tok, err := signJWT(subject, []string{"sovereign"}, signingKey, keyID)
			require.NoError(t, err)

			body, _ := json.Marshal(RegisterBeginRequest{PublicKeyPEM: pubPEM, DeviceId: "attacker-device", DeviceName: "n"})
			req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/begin?id="+url.QueryEscape(subject), bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			HandleRegisterBegin(kv)(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
			assert.NotContains(t, rec.Body.String(), "registrationToken", "no registration token may be issued for a non-person subject")
		})
	}
}

func TestRegisterBegin_XCheckDigitOrcid_Accepted(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, signingKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)
	_, pubPEM := testGenerateRSAKeyPair(t)
	orcid := "0000-0002-1825-009X"
	tok, err := signJWT(orcid, []string{"orcid"}, signingKey, keyID)
	require.NoError(t, err)

	body, _ := json.Marshal(RegisterBeginRequest{PublicKeyPEM: pubPEM, DeviceId: "d1", DeviceName: "n"})
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/begin?id="+orcid, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	HandleRegisterBegin(kv)(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code, "body: %s", rec.Body.String())
}

// A pending registration seeded under a non-person subject (for example one written
// before the begin gate existed) must not be promotable to a durable device key.
func TestRegisterCommit_NonPersonSubject_Refused(t *testing.T) {
	for name, subject := range nonPersonSubjects {
		if _, err := KK(subject, "pub", "keys", "attacker-device"); err != nil {
			// The key constructor itself refuses this id, so no pending key can be
			// seeded under it; the refusal is asserted here instead of skipped.
			t.Run(name+"-refused-by-key-constructor", func(t *testing.T) {
				assert.Error(t, err)
			})
			continue
		}
		t.Run(name, func(t *testing.T) {
			kv := setupTestKVStore(t)
			_, pubPEM := testGenerateRSAKeyPair(t)

			const token = "seededPendingToken0123456789"
			nonce := []byte("0123456789abcdef0123456789abcdef")
			pendingKey, err := KK(subject, "priv", "pending", token+".key")
			require.NoError(t, err)
			pendingNonce, err := KK(subject, "priv", "pending", token+".nonce")
			require.NoError(t, err)
			_, err = CmdSet(pendingKey, map[string]string{"x-id": subject}, []byte(pubPEM)).Exec()
			require.NoError(t, err)
			_, err = CmdSet(pendingNonce, map[string]string{"x-id": subject}, nonce).Exec()
			require.NoError(t, err)

			commitBody, _ := json.Marshal(RegisterCommitRequest{
				RegistrationToken: token,
				Nonce:             base64.StdEncoding.EncodeToString(nonce),
				DeviceId:          "attacker-device",
			})
			req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/commit?id="+url.QueryEscape(subject), bytes.NewReader(commitBody))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			HandleRegisterCommit(kv)(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
			promoted, err := KK(subject, "pub", "keys", "attacker-device")
			require.NoError(t, err)
			data, getErr := CmdGet(promoted).Exec()
			assert.True(t, getErr != nil || len(data) == 0, "no device key may be promoted under a non-person subject")
		})
	}
}
