// apps/backend/containers/id1/sync_assertion.go
//
// group: middleware
// tags: sync, jwt, assertion, rs256
// summary: Signs the short-lived assertion id1 attaches to its own backend
// dial (SyncProxy), by which the Automerge sync server learns a
// cryptographically attributable subject rather than a client-supplied claim.
//
//

package id1

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// syncAssertionAudience is the audience claim for the sync assertion.
// Deliberately distinct from jwtAudience() (which defaults to
// "curatorium-backend" and is what ordinary user JWTs carry, overridable via
// ID1_JWT_AUDIENCE) so a user JWT can never be replayed as a sync assertion.
// A fixed literal, never overridable.
const syncAssertionAudience = "curatorium-automerge-sync"

// syncAssertionTTL bounds the assertion's life. This is the connect window
// only, not the resulting socket's session life: the sync server verifies the
// assertion once, at the handshake (in a separate component/task), and the
// socket then persists for as long as the client stays connected. 60 seconds
// is ample for id1 to dial the backend and complete the WebSocket upgrade.
const syncAssertionTTL = 60 * time.Second

// syncAssertionClaims extends jwt.RegisteredClaims with the report-scope,
// write-verdict and grid-automerge-id fields the sync server's admission gate
// consults. Scope is "report", "unscoped" (the browser-minted grid-sync path,
// still ungated) or "grid" (a backend-minted grid ticket naming one Automerge
// id). ReportID and Write use `omitempty` and are
// populated only for a "report" scope mint; AutomergeID uses `omitempty` and
// is populated only for a "grid" scope mint - each scope's identifying claim
// is entirely absent, not zero-valued, on every other scope, so a decoder
// cannot mistake "no report"/"no grid id" for a zero value.
type syncAssertionClaims struct {
	Scope       string `json:"scope"`
	ReportID    int64  `json:"report_id,omitempty"`
	Write       string `json:"write,omitempty"`
	AutomergeID string `json:"automerge_id,omitempty"`
	jwt.RegisteredClaims
}

// mintSyncAssertion signs a short-lived RS256 assertion naming subject as the
// sync server's peer identity. scope is "report", "unscoped" or "grid";
// reportID and verdict are used only when scope is "report", automergeID
// only when scope is "grid" (every other combination ignores its
// scope-specific parameters, by convention passed as their zero value at the
// call site). It reuses id1's existing signing key (GetOrCreateSigningKey -
// the same key ordinary user JWTs are signed with) and the same issuer claim
// (jwtIssuer()), but a distinct audience (syncAssertionAudience).
func mintSyncAssertion(kvStore KeyValueStore, subject, scope string, reportID int64, verdict, automergeID string) (string, error) {
	keyID, privateKey, err := GetOrCreateSigningKey(kvStore)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := syncAssertionClaims{
		Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer(),
			Subject:   subject,
			Audience:  jwt.ClaimStrings{syncAssertionAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(syncAssertionTTL)),
		},
	}
	if scope == "report" {
		claims.ReportID = reportID
		claims.Write = verdict
	}
	if scope == "grid" {
		claims.AutomergeID = automergeID
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	return token.SignedString(privateKey)
}

// __END_OF_FILE_MARKER__
