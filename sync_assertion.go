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

// syncAssertionClaims extends jwt.RegisteredClaims with the report-scope and
// write-verdict fields the sync server's admission gate consults. Scope is
// "report" or "unscoped" (today's ungated grid-sync sessions, left untouched
// per the owner's "leave it alone" ruling on shared grid workspaces).
// ReportID and Write use `omitempty` and are populated only for a "report"
// scope mint - an unscoped assertion carries neither claim at all, rather
// than a zero-valued one, so a decoder cannot mistake "no report" for
// "report 0".
type syncAssertionClaims struct {
	Scope    string `json:"scope"`
	ReportID int64  `json:"report_id,omitempty"`
	Write    string `json:"write,omitempty"`
	jwt.RegisteredClaims
}

// mintSyncAssertion signs a short-lived RS256 assertion naming subject as the
// sync server's peer identity. scope is "report" or "unscoped"; reportID and
// verdict are used only when scope is "report" (an unscoped mint ignores
// them, by convention passed as 0 and "" at the call site). It reuses id1's
// existing signing key (GetOrCreateSigningKey - the same key ordinary user
// JWTs are signed with) and the same issuer claim (jwtIssuer()), but a
// distinct audience (syncAssertionAudience).
func mintSyncAssertion(kvStore KeyValueStore, subject, scope string, reportID int64, verdict string) (string, error) {
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

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	return token.SignedString(privateKey)
}

// __END_OF_FILE_MARKER__
