// apps/backend/containers/id1/refresh.go
//
// group: jwt
// tags: jwt, refresh, rs256
// summary: Token-for-token /auth/refresh endpoint. Re-mints a fresh 1h JWT from
// a still-valid one, carrying auth_time forward, capped at a 7-day session ceiling.
//

package id1

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// maxSessionTTL caps how long a session may be silently renewed before the user
// must re-authenticate with their sovereign key. Matches the 7-day sovereign
// public-key TTL (sovereign_register.go pubKeyTTL).
const maxSessionTTL = 7 * 24 * time.Hour

// HandleRefresh re-mints a fresh 1h JWT from a still-valid one (token-for-token),
// carrying auth_time forward. It refuses expired tokens (a lapsed token is dead)
// and tokens whose auth_time is older than maxSessionTTL. Claims parsing is
// strict: a missing or non-numeric auth_time yields nil and is rejected.
func HandleRefresh(kvStore KeyValueStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := ValidateRS256JWTID1Claims(tokenStr, kvStore)
		if err != nil { // bad signature OR expired
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		if claims.AuthTime == nil {
			http.Error(w, "Token not refreshable", http.StatusUnauthorized)
			return
		}
		if time.Since(claims.AuthTime.Time) > maxSessionTTL {
			http.Error(w, "Session expired, re-authentication required", http.StatusUnauthorized)
			return
		}

		keyID, privKey, err := GetOrCreateSigningKey(kvStore)
		if err != nil {
			http.Error(w, "signing key unavailable", http.StatusInternalServerError)
			return
		}
		fresh, err := signJWTWithAuthTime(claims.Subject, privKey, keyID, claims.AuthTime.Time)
		if err != nil {
			http.Error(w, "failed to issue token", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"jwt": fresh})
	}
}
