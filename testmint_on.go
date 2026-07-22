//go:build testmint

package id1

import (
	"fmt"
	"net/http"
	"os"
)

// RegisterTestMintRoutes registers the arbitrary-ORCID mint at /auth/test_user.
// The handler exists only in a binary built with the `testmint` tag, and even
// then registers only when ENV is dev or test.
func RegisterTestMintRoutes(mux *http.ServeMux, kvStore KeyValueStore) {
	if !IsDevOrTestEnv(os.Getenv("ENV")) {
		return
	}
	mux.HandleFunc("/auth/test_user", HandleTestUser(kvStore))
}

// HandleTestUser returns an HTTP handler that issues a test JWT for an arbitrary
// ORCID. It is compiled in only under the `testmint` build tag. It uses the same
// signing infrastructure as the ORCID callback.
func HandleTestUser(kvStore KeyValueStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		orcidID := r.URL.Query().Get("orcid")
		if orcidID == "" {
			orcidID = "0000-0002-1825-0097"
		}

		// Validate ORCID format
		if !orcidIDPattern.MatchString(orcidID) {
			http.Error(w, "Invalid ORCID iD format", http.StatusBadRequest)
			return
		}

		// Optional ?amr= override (default "test"), whitelisted to the known
		// mint-path values so the backend's provisioning gate can be exercised
		// with a chosen provenance. An unknown value is rejected rather than
		// silently defaulted.
		amr := r.URL.Query().Get("amr")
		if amr == "" {
			amr = "test"
		}
		if !isKnownAMR(amr) {
			http.Error(w, "Invalid amr value", http.StatusBadRequest)
			return
		}

		keyID, privKey, err := GetOrCreateSigningKey(kvStore)
		if err != nil {
			http.Error(w, "Failed to get signing key", http.StatusInternalServerError)
			return
		}

		jwtToken, err := signJWT(orcidID, []string{amr}, privKey, keyID)
		if err != nil {
			http.Error(w, "Failed to sign JWT", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jwt":%q}`, jwtToken)
	}
}

// isKnownAMR reports whether v is one of the recognised authentication-method-reference
// (mint-path provenance) values. Used to whitelist the /auth/test_user ?amr= override.
func isKnownAMR(v string) bool {
	switch v {
	case "test", "orcid", "sovereign", "demo":
		return true
	default:
		return false
	}
}
