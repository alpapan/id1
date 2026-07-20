// apps/backend/containers/id1/refresh_test.go
//
// group: jwt
// tags: jwt, refresh, rs256, testing
// summary: Tests for the token-for-token /auth/refresh endpoint.
//

package id1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleRefresh_ValidToken_ReturnsFreshTokenSameAuthTime(t *testing.T) {
	kv := setupTestKVStore(t)
	kid, priv, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)
	authTime := time.Now().Add(-3 * time.Hour)
	original, err := signJWTWithAuthTime("0000-0001-2345-6789", "", []string{"orcid"}, priv, kid, authTime)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+original)
	rec := httptest.NewRecorder()
	HandleRefresh(kv)(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var body struct {
		JWT string `json:"jwt"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))

	var fresh id1TokenClaims
	_, _, err = new(jwt.Parser).ParseUnverified(body.JWT, &fresh)
	require.NoError(t, err)
	require.NotNil(t, fresh.AuthTime)
	assert.LessOrEqual(t, fresh.AuthTime.Time.Sub(authTime).Abs(), time.Second, "auth_time not carried forward")
	assert.True(t, fresh.ExpiresAt.Time.After(time.Now().Add(50*time.Minute)), "exp not extended ~1h: %v", fresh.ExpiresAt)
}

func TestHandleRefresh_PastCeiling_401(t *testing.T) {
	kv := setupTestKVStore(t)
	kid, priv, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)
	old, err := signJWTWithAuthTime("0000-0001-2345-6789", "", []string{"orcid"}, priv, kid, time.Now().Add(-8*24*time.Hour))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+old)
	rec := httptest.NewRecorder()
	HandleRefresh(kv)(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleRefresh_MissingAuthTime_401(t *testing.T) {
	kv := setupTestKVStore(t)
	kid, priv, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)
	claims := id1TokenClaims{BootID: "x", RegisteredClaims: jwt.RegisteredClaims{
		Issuer: jwtIssuer(), Subject: "0000-0001-2345-6789",
		Audience:  jwt.ClaimStrings{jwtAudience()},
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}} // no AuthTime
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	legacy, err := tok.SignedString(priv)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+legacy)
	rec := httptest.NewRecorder()
	HandleRefresh(kv)(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleRefresh_NoBearer_401(t *testing.T) {
	rec := httptest.NewRecorder()
	HandleRefresh(setupTestKVStore(t))(rec, httptest.NewRequest(http.MethodPost, "/auth/refresh", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleRefresh_GET_405(t *testing.T) {
	rec := httptest.NewRecorder()
	HandleRefresh(setupTestKVStore(t))(rec, httptest.NewRequest(http.MethodGet, "/auth/refresh", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestHandleRefresh_CarriesAMRForward verifies a refreshed token keeps its mint-path
// provenance: a real-login token stays real (amr=["orcid"]) across renewal rather than
// silently downgrading to a provenance-less token.
func TestHandleRefresh_CarriesAMRForward(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, privKey, err := GetOrCreateSigningKey(kv)
	require.NoError(t, err)
	orig, err := signJWTWithAuthTime("0000-0001-2345-6789", "", []string{"orcid"}, privKey, keyID, time.Now())
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+orig)
	rec := httptest.NewRecorder()
	HandleRefresh(kv)(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		JWT string `json:"jwt"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	claims, err := ValidateRS256JWTID1Claims(body.JWT, kv)
	require.NoError(t, err)
	assert.Equal(t, []string{"orcid"}, claims.AMR, "refresh must carry amr forward so a real-login token stays real")
}
