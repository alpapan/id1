//go:build testmint

package id1

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testMintSecretForTests is the shared secret every handler test arms and presents.
const testMintSecretForTests = "unit-test-mint-secret-value"

// armTestMint sets the per-site secret the handler compares against.
func armTestMint(t *testing.T) {
	t.Helper()
	t.Setenv(testMintSecretEnv, testMintSecretForTests)
}

// mintGet builds a GET to the mint carrying the secret header.
func mintGet(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set(testMintSecretHeader, testMintSecretForTests)
	return req
}

func TestRegisterTestMintRoutes_RegistersInDevAndTestWhenOptedIn(t *testing.T) {
	for _, env := range []string{"dev", "test"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("ENV", env)
			t.Setenv(testMintEnableEnv, "on")
			armTestMint(t)
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
// dev or test, so a wrongly-deployed image does not re-open the endpoint. The
// opt-in being on does not override it, and an unset opt-in does not halt there.
func TestRegisterTestMintRoutes_RefusesOutsideDevAndTest(t *testing.T) {
	for _, env := range []string{"production", "prod", "", "TEST"} {
		for _, optIn := range []string{"on", ""} {
			t.Run(env+"/optin="+optIn, func(t *testing.T) {
				t.Setenv("ENV", env)
				t.Setenv(testMintEnableEnv, optIn)
				armTestMint(t)
				mux := http.NewServeMux()
				RegisterTestMintRoutes(mux, ID1KeyValueStore{})

				_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, "/auth/test_user", nil))
				if pattern != "" {
					t.Fatalf("ENV=%q registered /auth/test_user (pattern %q); only dev/test may", env, pattern)
				}
			})
		}
	}
}

// The per-site opt-in has no default: unset or unrecognised halts boot, and "off"
// registers nothing.
func TestRegisterTestMintRoutes_OptInHasNoDefault(t *testing.T) {
	armTestMint(t)
	t.Setenv("ENV", "test")
	for _, bad := range []string{"", "yes", "ON", "true", " on"} {
		t.Run("halts/"+bad, func(t *testing.T) {
			t.Setenv(testMintEnableEnv, bad)
			assert.Panics(t, func() { RegisterTestMintRoutes(http.NewServeMux(), ID1KeyValueStore{}) })
		})
	}
	t.Run("off", func(t *testing.T) {
		t.Setenv(testMintEnableEnv, "off")
		mux := http.NewServeMux()
		RegisterTestMintRoutes(mux, ID1KeyValueStore{})
		_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, "/auth/test_user", nil))
		assert.Empty(t, pattern)
	})
}

// With the opt-in on and no secret, the route must never open: boot halts.
func TestRegisterTestMintRoutes_OnWithoutSecretHalts(t *testing.T) {
	t.Setenv("ENV", "test")
	t.Setenv(testMintEnableEnv, "on")
	t.Setenv(testMintSecretEnv, "")
	assert.Panics(t, func() { RegisterTestMintRoutes(http.NewServeMux(), ID1KeyValueStore{}) })
}

func TestHandleTestUser_RequiresTheSecretHeader(t *testing.T) {
	kv := setupTestKVStore(t)
	armTestMint(t)
	handler := HandleTestUser(kv)
	cases := map[string]string{
		"missing":          "",
		"wrong":            "not-the-secret",
		"prefix-of-secret": testMintSecretForTests[:5],
		"secret-plus-more": testMintSecretForTests + "x",
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/auth/test_user?orcid=0000-0000-0000-0028", nil)
			if header != "" {
				req.Header.Set(testMintSecretHeader, header)
			}
			rec := httptest.NewRecorder()
			handler(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.NotContains(t, rec.Body.String(), "jwt")
		})
	}
	t.Run("correct", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler(rec, mintGet("/auth/test_user?orcid=0000-0000-0000-0028"))
		assert.Equal(t, http.StatusOK, rec.Code)
	})
	// The default-iD path (no query string) is the exposure the gate closes.
	t.Run("default-iD-without-header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/auth/test_user", nil))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

// An unset server-side secret never matches, not even an empty header: the handler
// fails closed even when built without going through RegisterTestMintRoutes.
func TestHandleTestUser_UnsetSecretRefusesEveryCaller(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv(testMintSecretEnv, "")
	for _, header := range []string{"", "anything"} {
		req := httptest.NewRequest(http.MethodGet, "/auth/test_user?orcid=0000-0000-0000-0028", nil)
		if header != "" {
			req.Header.Set(testMintSecretHeader, header)
		}
		rec := httptest.NewRecorder()
		HandleTestUser(kv)(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "header %q", header)
		assert.NotContains(t, rec.Body.String(), "jwt")
	}
}

// The mint records who received a token (iD, amr, caller address) and never the token.
func TestHandleTestUser_LogsTheMintWithoutTheToken(t *testing.T) {
	kv := setupTestKVStore(t)
	armTestMint(t)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	req := mintGet("/auth/test_user?orcid=0000-0000-0000-0036")
	req.RemoteAddr = "192.0.2.7:4242"
	rec := httptest.NewRecorder()
	HandleTestUser(kv)(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		JWT string `json:"jwt"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	line := buf.String()
	assert.Contains(t, line, "0000-0000-0000-0036")
	assert.Contains(t, line, "test")
	assert.Contains(t, line, "192.0.2.7")
	assert.NotContains(t, line, body.JWT)
	assert.NotContains(t, line, testMintSecretForTests)
}

// End-to-end: a real issuer (HandleTestUser) must produce auth_time, proving no
// issuer constructs claims manually and bypasses signJWT. Compiled in only
// under the `testmint` build tag.
func TestHandleTestUser_StampsAuthTime(t *testing.T) {
	t.Setenv("ENV", "test")
	kv := setupTestKVStore(t)
	armTestMint(t)
	req := mintGet("/auth/test_user?orcid=0000-0000-0009-0019")
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
	armTestMint(t)
	handler := HandleTestUser(kvStore)

	t.Run("GET returns JWT for provided ORCID", func(t *testing.T) {
		req := mintGet("/auth/test_user?orcid=0000-0000-0009-0027")
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
		req := mintGet("/auth/test_user?orcid=not-an-orcid")
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("GET with no ORCID returns JWT with default ORCID", func(t *testing.T) {
		req := mintGet("/auth/test_user")
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
// ?amr= override limited to the values only a test or demo mint may stamp, and
// rejects every other value, including the real-login provenances "orcid" and
// "sovereign", which only the ORCID callback and the device-key sign-in may stamp.
// Compiled in only under the `testmint` build tag.
func TestHandleTestUser_AMRParam(t *testing.T) {
	kv := setupTestKVStore(t)
	armTestMint(t)
	for _, amr := range []string{"test", "demo"} {
		rec := httptest.NewRecorder()
		HandleTestUser(kv)(rec, mintGet("/auth/test_user?orcid=0000-0000-0009-0035&amr="+amr))
		require.Equal(t, http.StatusOK, rec.Code, amr)
		var body struct {
			JWT string `json:"jwt"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		claims, err := ValidateRS256JWTID1Claims(body.JWT, kv)
		require.NoError(t, err)
		assert.Equal(t, []string{amr}, claims.AMR)
	}
	for _, amr := range []string{"orcid", "sovereign", "bogus"} {
		rec := httptest.NewRecorder()
		HandleTestUser(kv)(rec, mintGet("/auth/test_user?orcid=0000-0000-0009-0035&amr="+amr))
		assert.Equal(t, http.StatusBadRequest, rec.Code, amr)
		assert.NotContains(t, rec.Body.String(), "jwt", amr)
	}
}

// TestHandleTestUser_StampsTestAMR verifies the test-helper mint stamps
// amr=["test"] by default, so its tokens are distinguishable from a real
// login. Compiled in only under the `testmint` build tag.
func TestHandleTestUser_StampsTestAMR(t *testing.T) {
	kv := setupTestKVStore(t)
	armTestMint(t)
	rec := httptest.NewRecorder()
	HandleTestUser(kv)(rec, mintGet("/auth/test_user?orcid=0000-0000-0009-0035"))
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
	demoUser := requireDemoUserSetting(t)
	for _, orcid := range []string{
		"0000-0000-0000-0001",
		"0000-0000-0000-0002",
		"0000-0000-0000-0004",
		"0000-0000-0000-0007",
		"0000-0000-0000-0008",
		"0000-0000-0000-0009",
		demoUser,
		"0000-0000-0000-0028",
	} {
		assert.True(t, isTestMintOrcid(orcid), orcid)
	}
	for _, orcid := range []string{
		"0000-0000-0000-0010",
		"0000-0002-1825-0097",
	} {
		assert.False(t, isTestMintOrcid(orcid), orcid)
	}
}

func TestHandleTestUser_RefusesAnIDOutsideTheReservedRange(t *testing.T) {
	kv := setupTestKVStore(t)
	armTestMint(t)
	handler := HandleTestUser(kv)
	for _, orcid := range []string{"0000-0002-1825-0097", "0000-0000-0000-0029"} {
		rec := httptest.NewRecorder()
		handler(rec, mintGet("/auth/test_user?orcid="+orcid))
		assert.Equal(t, http.StatusForbidden, rec.Code, orcid)
		assert.Contains(t, rec.Body.String(), "ORCID iD outside the reserved test range", orcid)
		assert.NotContains(t, rec.Body.String(), "jwt", orcid)
	}
}

func TestHandleTestUser_SignsTheFixedIdentitiesOutsideTheRange(t *testing.T) {
	kv := setupTestKVStore(t)
	armTestMint(t)
	handler := HandleTestUser(kv)
	_, privKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)
	fixedIdentities := []string{"0000-0000-0000-0001", "0000-0000-0000-0002", "0000-0000-0000-0003", "0000-0000-0000-0004", "0000-0000-0000-0005", "0000-0000-0000-0006", "0000-0000-0000-0007", "0000-0000-0000-0008", "0000-0000-0000-0009", requireDemoUserSetting(t)}
	for _, orcid := range fixedIdentities {
		rec := httptest.NewRecorder()
		handler(rec, mintGet("/auth/test_user?orcid="+orcid))
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
