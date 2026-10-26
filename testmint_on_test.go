//go:build testmint

package id1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterTestMintRoutes_RegistersInDevAndTest(t *testing.T) {
	for _, env := range []string{"dev", "test"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("ENV", env)
			mux := http.NewServeMux()
			RegisterTestMintRoutes(mux, ID1KeyValueStore{})

			_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, "/auth/test_user", nil))
			if pattern == "" {
				t.Fatalf("ENV=%s: /auth/test_user was not registered under the testmint tag", env)
			}
		})
	}
}

// Even a testmint-tagged binary must refuse to register the mint when ENV is not
// dev or test, so a wrongly-deployed image does not re-open the endpoint.
func TestRegisterTestMintRoutes_RefusesOutsideDevAndTest(t *testing.T) {
	for _, env := range []string{"production", "prod", "", "TEST"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("ENV", env)
			mux := http.NewServeMux()
			RegisterTestMintRoutes(mux, ID1KeyValueStore{})

			_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, "/auth/test_user", nil))
			if pattern != "" {
				t.Fatalf("ENV=%q registered /auth/test_user (pattern %q); only dev/test may", env, pattern)
			}
		})
	}
}

// End-to-end: a real issuer (HandleTestUser) must produce auth_time, proving no
// issuer constructs claims manually and bypasses signJWT. Compiled in only
// under the `testmint` build tag.
func TestHandleTestUser_StampsAuthTime(t *testing.T) {
	t.Setenv("ENV", "test")
	kv := setupTestKVStore(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/test_user?orcid=0000-0000-0009-0019", nil)
	rec := httptest.NewRecorder()
	HandleTestUser(kv)(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var body struct {
		JWT string `json:"jwt"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	var claims id1TokenClaims
	_, _, err := new(jwt.Parser).ParseUnverified(body.JWT, &claims)
	require.NoError(t, err)
	require.NotNil(t, claims.AuthTime, "issuer did not stamp auth_time")
}

// TestHandleTestUser exercises the arbitrary-ORCID mint. Compiled in only
// under the `testmint` build tag.
func TestHandleTestUser(t *testing.T) {
	kvStore := setupTestKVStore(t)
	handler := HandleTestUser(kvStore)

	t.Run("GET returns JWT for provided ORCID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/test_user?orcid=0000-0000-0009-0027", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if resp["jwt"] == "" {
			t.Fatal("expected non-empty jwt")
		}
		_, privKey, err := GetOrCreateSigningKey(kvStore)
		if err != nil {
			t.Fatalf("failed to get signing key: %v", err)
		}
		token, parseErr := jwt.ParseWithClaims(resp["jwt"], &jwt.RegisteredClaims{}, func(tok *jwt.Token) (interface{}, error) {
			return &privKey.PublicKey, nil
		})
		if parseErr != nil {
			t.Fatalf("JWT should be cryptographically valid: %v", parseErr)
		}
		claims, ok := token.Claims.(*jwt.RegisteredClaims)
		if !ok {
			t.Fatal("claims should be RegisteredClaims")
		}
		if claims.Subject != "0000-0000-0009-0027" {
			t.Errorf("expected subject %q, got %q", "0000-0000-0009-0027", claims.Subject)
		}
	})

	t.Run("GET with invalid ORCID returns 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/test_user?orcid=not-an-orcid", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("GET with no ORCID returns JWT with default ORCID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/test_user", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		_, privKey, err := GetOrCreateSigningKey(kvStore)
		if err != nil {
			t.Fatalf("failed to get signing key: %v", err)
		}
		token, parseErr := jwt.ParseWithClaims(resp["jwt"], &jwt.RegisteredClaims{}, func(tok *jwt.Token) (interface{}, error) {
			return &privKey.PublicKey, nil
		})
		if parseErr != nil {
			t.Fatalf("default-ORCID JWT should be cryptographically valid: %v", parseErr)
		}
		claims, ok := token.Claims.(*jwt.RegisteredClaims)
		if !ok {
			t.Fatal("claims should be RegisteredClaims")
		}
		const defaultORCID = "0000-0000-0000-0028"
		if claims.Subject != defaultORCID {
			t.Errorf("expected default ORCID %q as subject, got %q", defaultORCID, claims.Subject)
		}
	})

	t.Run("POST returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/test_user", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", w.Code)
		}
	})
}

// TestHandleTestUser_AMRParam verifies the test-helper mint honours an optional
// whitelisted ?amr= override (so a caller can mint a token with a chosen
// mint-path provenance) and rejects an unknown value. Compiled in only under
// the `testmint` build tag.
func TestHandleTestUser_AMRParam(t *testing.T) {
	kv := setupTestKVStore(t)
	// chosen amr honoured
	rec := httptest.NewRecorder()
	HandleTestUser(kv)(rec, httptest.NewRequest(http.MethodGet, "/auth/test_user?orcid=0000-0000-0009-0035&amr=orcid", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		JWT string `json:"jwt"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	claims, err := ValidateRS256JWTID1Claims(body.JWT, kv)
	require.NoError(t, err)
	assert.Equal(t, []string{"orcid"}, claims.AMR)
	// unknown amr rejected
	rec2 := httptest.NewRecorder()
	HandleTestUser(kv)(rec2, httptest.NewRequest(http.MethodGet, "/auth/test_user?orcid=0000-0000-0009-0035&amr=bogus", nil))
	assert.Equal(t, http.StatusBadRequest, rec2.Code)
}

// TestHandleTestUser_StampsTestAMR verifies the test-helper mint stamps
// amr=["test"] by default, so its tokens are distinguishable from a real
// login. Compiled in only under the `testmint` build tag.
func TestHandleTestUser_StampsTestAMR(t *testing.T) {
	kv := setupTestKVStore(t)
	rec := httptest.NewRecorder()
	HandleTestUser(kv)(rec, httptest.NewRequest(http.MethodGet, "/auth/test_user?orcid=0000-0000-0009-0035", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		JWT string `json:"jwt"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	claims, err := ValidateRS256JWTID1Claims(body.JWT, kv)
	require.NoError(t, err)
	assert.Contains(t, claims.AMR, "test")
}

func TestIsReservedTestOrcid(t *testing.T) {
	accepted := []string{
		"0000-0000-0000-001X",
		"0000-0000-0000-0028",
		"0000-0000-0000-0036",
		"0000-0000-0000-0044",
		"0000-0000-0000-0052",
		"0000-0000-1000-0005",
		"0000-0000-5338-7318",
		"0000-0000-9999-9993",
	}
	for _, orcid := range accepted {
		assert.True(t, isReservedTestOrcid(orcid), orcid)
	}
	refused := []string{
		"0000-0000-0000-0001", // body 0
		"0000-0000-0000-0029", // wrong check character
		"0000-0002-1825-0097", // ORCID's published example, in its issuing block
		"0000-0001-0000-0009", // checksum-valid, outside 0000-0000-
		"0009-8218-8338-7312",
		"0000-0000-0000-002",
		"0000-0000-0000-00280",
		"0000-0000-0000-002x",
		"not-an-orcid",
		"",
	}
	for _, orcid := range refused {
		assert.False(t, isReservedTestOrcid(orcid), orcid)
	}
}

func TestIsTestMintOrcid(t *testing.T) {
	for _, orcid := range []string{
		"0000-0000-0000-0001",
		"0000-0000-0000-0004",
		"0000-0000-0000-0007",
		"0000-0000-0000-0008",
		"0000-0000-0000-0009",
		"0009-0009-9355-3782",
		"0000-0000-0000-0028",
	} {
		assert.True(t, isTestMintOrcid(orcid), orcid)
	}
	for _, orcid := range []string{
		"0000-0000-0000-0002",
		"0000-0000-0000-0010",
		"0009-0002-8023-3658",
		"0000-0002-1825-0097",
	} {
		assert.False(t, isTestMintOrcid(orcid), orcid)
	}
}

func TestHandleTestUser_RefusesAnIDOutsideTheReservedRange(t *testing.T) {
	kv := setupTestKVStore(t)
	handler := HandleTestUser(kv)
	for _, orcid := range []string{"0000-0002-1825-0097", "0000-0000-0000-0029", "0009-0002-8023-3658", "0000-0000-0000-0002"} {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/auth/test_user?orcid="+orcid, nil))
		assert.Equal(t, http.StatusForbidden, rec.Code, orcid)
		assert.Contains(t, rec.Body.String(), "ORCID iD outside the reserved test range", orcid)
		assert.NotContains(t, rec.Body.String(), "jwt", orcid)
	}
}

func TestHandleTestUser_SignsTheFixedIdentitiesOutsideTheRange(t *testing.T) {
	kv := setupTestKVStore(t)
	handler := HandleTestUser(kv)
	_, privKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)
	for _, orcid := range []string{"0000-0000-0000-0001", "0000-0000-0000-0003", "0000-0000-0000-0004", "0000-0000-0000-0005", "0000-0000-0000-0006", "0000-0000-0000-0007", "0000-0000-0000-0008", "0000-0000-0000-0009", "0009-0009-9355-3782"} {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/auth/test_user?orcid="+orcid, nil))
		require.Equal(t, http.StatusOK, rec.Code, orcid)
		var resp map[string]string
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), orcid)
		token, parseErr := jwt.ParseWithClaims(resp["jwt"], &jwt.RegisteredClaims{}, func(tok *jwt.Token) (interface{}, error) {
			return &privKey.PublicKey, nil
		})
		require.NoError(t, parseErr, orcid)
		claims, ok := token.Claims.(*jwt.RegisteredClaims)
		require.True(t, ok, orcid)
		assert.Equal(t, orcid, claims.Subject)
	}
}
