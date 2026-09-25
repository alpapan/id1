// apps/id1/sync_assertion_test.go
//
// group: middleware
// tags: sync, jwt, assertion, testing
// summary: Tests for the signed sync assertion id1 mints for the Automerge sync server.
//
//

package id1

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseSyncAssertion verifies tokenStr against kv's signing key and returns
// its claims, for test assertions only.
func parseSyncAssertion(t *testing.T, kv KeyValueStore, tokenStr string) syncAssertionClaims {
	t.Helper()
	rsaPubKey, err := resolveSigningPublicKey(kv)
	require.NoError(t, err)
	var claims syncAssertionClaims
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(tok *jwt.Token) (any, error) {
		return rsaPubKey, nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)
	return claims
}

// TestMintSyncAssertion_ReportScope verifies a report-scoped mint carries the
// subject, "report" scope, report id and verdict, a distinct audience from
// ordinary user JWTs, and an issuer matching jwtIssuer().
func TestMintSyncAssertion_ReportScope(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_JWT_ISSUER", "https://id1.example.test")
	tokenStr, err := mintSyncAssertion(kv, "0000-0001-2345-6789", "report", 42, "allowed", "")
	require.NoError(t, err)

	claims := parseSyncAssertion(t, kv, tokenStr)
	assert.Equal(t, "0000-0001-2345-6789", claims.Subject)
	assert.Equal(t, "report", claims.Scope)
	assert.Equal(t, int64(42), claims.ReportID)
	assert.Equal(t, "allowed", claims.Write)
	assert.Equal(t, "https://id1.example.test", claims.Issuer)
	require.Len(t, claims.Audience, 1)
	assert.Equal(t, syncAssertionAudience, claims.Audience[0])
	assert.NotEqual(t, defaultJWTAudience, claims.Audience[0],
		"the sync assertion audience must differ from the ordinary user-JWT audience, so a user "+
			"JWT can never be replayed as a sync assertion")
}

// TestMintSyncAssertion_UnscopedOmitsReportFields verifies an unscoped (grid)
// mint carries no report_id/write claims at all - not merely zero-valued ones -
// so a decoder cannot mistake "no report" for "report 0".
func TestMintSyncAssertion_UnscopedOmitsReportFields(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_JWT_ISSUER", "https://id1.example.test")
	tokenStr, err := mintSyncAssertion(kv, "0000-0001-2345-6789", "unscoped", 0, "", "")
	require.NoError(t, err)

	claims := parseSyncAssertion(t, kv, tokenStr)
	assert.Equal(t, "unscoped", claims.Scope)
	assert.Equal(t, int64(0), claims.ReportID)
	assert.Equal(t, "", claims.Write)
}

// TestMintSyncAssertion_ShortLived verifies the assertion expires quickly -
// this is the connect window, not the resulting socket's session life.
func TestMintSyncAssertion_ShortLived(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_JWT_ISSUER", "https://id1.example.test")
	tokenStr, err := mintSyncAssertion(kv, "0000-0001-2345-6789", "report", 1, "allowed", "")
	require.NoError(t, err)
	claims := parseSyncAssertion(t, kv, tokenStr)
	lifetime := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
	assert.Equal(t, syncAssertionTTL, lifetime)
	assert.LessOrEqual(t, lifetime.Seconds(), float64(120), "the assertion must be short-lived: a connect window, not a session credential")
}

// TestMintSyncAssertion_RejectsUnsetIssuer verifies mintSyncAssertion panics
// (via jwtIssuer's own no-default panic) when ID1_JWT_ISSUER is unset, the
// same fail-fast behaviour signJWT already has - never a silently blank issuer.
func TestMintSyncAssertion_RejectsUnsetIssuer(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_JWT_ISSUER", "")
	assert.Panics(t, func() {
		_, _ = mintSyncAssertion(kv, "0000-0001-2345-6789", "report", 1, "allowed", "")
	})
}

// TestMintSyncAssertion_GridScope verifies a grid-scoped mint carries the
// subject, "grid" scope and the automerge id, with no report_id/write claims
// set at all. reportID and verdict are passed as a non-zero id and a
// caller-supplied verdict (as a caller might, by mistake or malice), to
// prove the grid scope actually drops them - passing their zero values
// would still pass even if mintSyncAssertion's `scope == "report"` guard
// were deleted entirely.
func TestMintSyncAssertion_GridScope(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_JWT_ISSUER", "https://id1.example.test")
	tokenStr, err := mintSyncAssertion(kv, "0000-0001-2345-6789", "grid", 99, "allowed", "4NMNbHrKADgnbtGJVXVyubc4")
	require.NoError(t, err)

	claims := parseSyncAssertion(t, kv, tokenStr)
	assert.Equal(t, "0000-0001-2345-6789", claims.Subject)
	assert.Equal(t, "grid", claims.Scope)
	assert.Equal(t, "4NMNbHrKADgnbtGJVXVyubc4", claims.AutomergeID)
	assert.Equal(t, int64(0), claims.ReportID)
	assert.Equal(t, "", claims.Write)
}

// TestMintSyncAssertion_NonGridScopesOmitAutomergeID verifies neither a
// report-scoped nor an unscoped mint ever carries an automerge_id claim -
// the field is exclusive to the grid scope. Both mints pass a real automerge
// id (as a caller might, by mistake or malice) to prove it is the scope
// guard doing the omitting, not simply that no id was ever supplied - a test
// passing "" for both would still pass if the `scope == "grid"` guard in
// mintSyncAssertion were deleted entirely.
func TestMintSyncAssertion_NonGridScopesOmitAutomergeID(t *testing.T) {
	kv := setupTestKVStore(t)
	t.Setenv("ID1_JWT_ISSUER", "https://id1.example.test")
	const suppliedAutomergeID = "4NMNbHrKADgnbtGJVXVyubc4"

	reportToken, err := mintSyncAssertion(kv, "0000-0001-2345-6789", "report", 42, "allowed", suppliedAutomergeID)
	require.NoError(t, err)
	reportClaims := parseSyncAssertion(t, kv, reportToken)
	assert.Equal(t, "", reportClaims.AutomergeID)

	unscopedToken, err := mintSyncAssertion(kv, "0000-0001-2345-6789", "unscoped", 0, "", suppliedAutomergeID)
	require.NoError(t, err)
	unscopedClaims := parseSyncAssertion(t, kv, unscopedToken)
	assert.Equal(t, "", unscopedClaims.AutomergeID)
}
