//go:build curatoriumdemo

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

// With the `curatoriumdemo` build tag - Curatorium's own deployment shape -
// the demo-identity mint must be registered, unconditionally: the four demo
// pages are production surface and depend on it in every environment,
// production included.
func TestRegisterDemoRoutes_RegistersUnconditionally(t *testing.T) {
	mux := http.NewServeMux()
	RegisterDemoRoutes(mux, ID1KeyValueStore{})

	_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, "/auth/unauth_demo", nil))
	if pattern == "" {
		t.Fatal("curatoriumdemo build did not register /auth/unauth_demo")
	}
}

func TestHandleDemoUser(t *testing.T) {
	kvStore := setupTestKVStore(t)

	handler := HandleDemoUser(kvStore)

	t.Run("GET returns JWT for demo_user ORCID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/unauth_demo", nil)
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

		// Validate JWT is cryptographically valid and contains correct claims
		_, privKey, err := GetOrCreateSigningKey(kvStore) // same kvStore as the handler used
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
		if claims.Subject != demoUserORCID {
			t.Errorf("expected subject %q, got %q", demoUserORCID, claims.Subject)
		}
	})

	t.Run("POST returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/unauth_demo", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", w.Code)
		}
	})
}

// TestHandleDemoUser_MintsNonAdminDemoUser verifies the public demo endpoint mints
// the seeded NON-admin demo user, never the admin ORCID, and stamps amr=["demo"].
func TestHandleDemoUser_MintsNonAdminDemoUser(t *testing.T) {
	kv := setupTestKVStore(t)
	rec := httptest.NewRecorder()
	HandleDemoUser(kv)(rec, httptest.NewRequest(http.MethodGet, "/auth/unauth_demo", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		JWT string `json:"jwt"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	claims, err := ValidateRS256JWTID1Claims(body.JWT, kv)
	require.NoError(t, err)
	assert.Equal(t, "0009-0009-9355-3782", claims.Subject,
		"demo endpoint must mint the non-admin demo user, never the admin ORCID 0009-0002-8023-3658")
	assert.Contains(t, claims.AMR, "demo")
}
