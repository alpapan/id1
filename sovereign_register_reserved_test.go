// group: auth
// tags: sovereign-keys, registration, reserved-block, demo, refresh, security
// summary: The public device-registration path and /auth/refresh refuse the identities
// that sign in only through trusted paths: the reserved 0000-0000- block, the demo
// user, and (for refresh) any token whose amr says demo.

package id1

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// trustedPathOnlyOrcids returns identities the public enrolment path must refuse. The
// demo iD sits outside the reserved block, as ORCID_DEMO_USER does in .env.test.
func trustedPathOnlyOrcids(t *testing.T) map[string]string {
	t.Helper()
	const demo = "0000-0002-1825-0097"
	t.Setenv("ORCID_DEMO_USER", demo)
	return map[string]string{
		"system-account":          "0000-0000-0000-0001",
		"files-account":           "0000-0000-0000-0002",
		"test-identity":           "0000-0000-0000-0028",
		"wrong-check-in-block":    "0000-0000-0000-0029",
		"top-of-block":            "0000-0000-9999-9993",
		"demo-user-outside-block": demo,
	}
}

func TestRegisterBegin_TrustedPathOnlyIdentity_Refused(t *testing.T) {
	for name, orcid := range trustedPathOnlyOrcids(t) {
		t.Run(name, func(t *testing.T) {
			kv := setupTestKVStore(t)
			keyID, signingKey, err := GetOrCreateSigningKey(kv)
			require.NoError(t, err)
			_, pubPEM := testGenerateRSAKeyPair(t)
			// Valid RS256 JWT whose subject equals ?id, with a real-login amr: the
			// refusal must hold whatever the token carries.
			tok, err := signJWT(orcid, []string{"orcid"}, signingKey, keyID)
			require.NoError(t, err)

			body, _ := json.Marshal(RegisterBeginRequest{PublicKeyPEM: pubPEM, DeviceId: "attacker-device", DeviceName: "n"})
			req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/begin?id="+orcid, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			HandleRegisterBegin(kv)(rec, req)

			assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
			assert.NotContains(t, rec.Body.String(), "registrationToken")
			assert.False(t, idExists(orcid), "no key may be stored for %s", orcid)
		})
	}
}

func TestRegisterCommit_TrustedPathOnlyIdentity_Refused(t *testing.T) {
	for name, orcid := range trustedPathOnlyOrcids(t) {
		t.Run(name, func(t *testing.T) {
			setupTestKVStore(t)
			body, _ := json.Marshal(RegisterCommitRequest{
				RegistrationToken: strings.Repeat("A", 43),
				Nonce:             "AAAA",
				DeviceId:          "attacker-device",
			})
			req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/commit?id="+orcid, bytes.NewReader(body))
			rec := httptest.NewRecorder()
			HandleRegisterCommit(ID1KeyValueStore{})(rec, req)

			assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
		})
	}
}

// With no demo user declared, an empty setting must name no iD: a researcher's iD is
// still enrolled normally.
func TestRegisterBegin_ResearcherStillEnrols_WhenDemoUserUnset(t *testing.T) {
	t.Setenv("ORCID_DEMO_USER", "")
	kv := setupTestKVStore(t)
	keyID, signingKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)
	_, pubPEM := testGenerateRSAKeyPair(t)
	const researcher = "0000-0002-1825-0097"
	tok, err := signJWT(researcher, []string{"orcid"}, signingKey, keyID)
	require.NoError(t, err)

	body, _ := json.Marshal(RegisterBeginRequest{PublicKeyPEM: pubPEM, DeviceId: "d1", DeviceName: "n"})
	req := httptest.NewRequest(http.MethodPost, "/auth/sovereign/register/begin?id="+researcher, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	HandleRegisterBegin(kv)(rec, req)
	assert.Equal(t, http.StatusAccepted, rec.Code, "body: %s", rec.Body.String())
}

func TestHandleRefresh_RefusesADemoToken(t *testing.T) {
	kv := setupTestKVStore(t)
	kid, priv, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)
	for _, amr := range [][]string{{"demo"}, {"orcid", "demo"}} {
		tok, err := signJWTWithAuthTime("0000-0002-1825-0097", "", amr, priv, kid, time.Now())
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		HandleRefresh(kv)(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "amr %v body: %s", amr, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), "jwt", "amr %v", amr)
	}
}
