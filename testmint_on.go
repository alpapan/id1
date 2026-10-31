//go:build testmint

package id1

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
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
			orcidID = "0000-0000-0000-0028"
		}

		// Validate ORCID format
		if !orcidIDPattern.MatchString(orcidID) {
			http.Error(w, "Invalid ORCID iD format", http.StatusBadRequest)
			return
		}

		// Sign only a test identity: a researcher's iD is never minted here.
		if !isTestMintOrcid(orcidID) {
			http.Error(w, "ORCID iD outside the reserved test range", http.StatusForbidden)
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

// reservedTestOrcidPrefix opens every iD of the reserved test range. ORCID issues no
// iD in the 0000-0000- block.
const reservedTestOrcidPrefix = "0000-0000-"

// testMintFixedIdentities are the identities outside the reserved test range that the
// deployment seeds itself and that tests sign in as: the system accounts
// 0000-0000-0000-0001 to 0000-0000-0000-0009 inclusive, and the demo user.
//
// 0000-0000-0000-0002 is the files account. It owns the shared folder's records
// and holds the admin role, and the seed steps that call the backend act as it.
var testMintFixedIdentities = map[string]bool{
	"0000-0000-0000-0001": true,
	"0000-0000-0000-0002": true,
	"0000-0000-0000-0003": true,
	"0000-0000-0000-0004": true,
	"0000-0000-0000-0005": true,
	"0000-0000-0000-0006": true,
	"0000-0000-0000-0007": true,
	"0000-0000-0000-0008": true,
	"0000-0000-0000-0009": true,
	"0009-0009-9355-3782": true,
}

// orcidCheckCharacter is the ISO 7064 MOD 11-2 check character of a fifteen-digit
// ORCID body.
func orcidCheckCharacter(body string) string {
	total := 0
	for _, ch := range body {
		total = (total + int(ch-'0')) * 2
	}
	result := (12 - total%11) % 11
	if result == 10 {
		return "X"
	}
	return strconv.Itoa(result)
}

// isReservedTestOrcid reports whether orcid is a checksum-valid iD whose first two
// groups are 0000-0000- and whose fifteen-digit body is 1 or more.
func isReservedTestOrcid(orcid string) bool {
	if !orcidIDPattern.MatchString(orcid) || !strings.HasPrefix(orcid, reservedTestOrcidPrefix) {
		return false
	}
	digits := strings.ReplaceAll(orcid, "-", "")
	body := digits[:15]
	if strings.Trim(body, "0") == "" {
		return false
	}
	return orcidCheckCharacter(body) == digits[15:]
}

// isTestMintOrcid reports whether the test mint may sign a token for orcid.
func isTestMintOrcid(orcid string) bool {
	return isReservedTestOrcid(orcid) || testMintFixedIdentities[orcid]
}
