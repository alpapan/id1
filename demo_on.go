//go:build curatoriumdemo

package id1

import (
	"fmt"
	"net/http"
	"os"
)

// RegisterDemoRoutes registers the demo-identity mint at /auth/unauth_demo.
// Compiled in only under the `curatoriumdemo` build tag - Curatorium's own
// deployment, where four demo pages depend on it as production surface,
// reached only through the frontend's rate-limited in-cluster proxy
// /api/demo/unauth-token, never directly. Unconditional here: no ENV check,
// because those pages are live in every Curatorium environment including
// production. annot8r_id1 must never carry this handler - see demo_off.go.
// The process stops at boot (panic, the same fail-fast as jwtIssuer) when
// ORCID_DEMO_USER is unset or is not an ORCID iD: there is no default iD.
func RegisterDemoRoutes(mux *http.ServeMux, kvStore KeyValueStore) {
	mustDemoUserORCID()
	mux.HandleFunc("/auth/unauth_demo", HandleDemoUser(kvStore))
}

// demoUserEnv names the setting that holds the ORCID iD of the seeded demo_user
// (migrations/seed/02b_user_core_seed.sql), granted all roles EXCEPT admin
// (migrations/seed/99_seed_tables.sql). The setting must name the NON-admin demo
// identity, never the iD that ORCID_SANDBOX_REAL_USER names (the real person, who is the
// administrator): minting an administrator from a public endpoint would hand anonymous
// callers an admin token. There is no default.
const demoUserEnv = "ORCID_DEMO_USER"

// lookupDemoUserORCID returns the demo user's iD from the setting. It reports false when
// the setting is unset or is not an ORCID iD, so every caller fails closed.
func lookupDemoUserORCID() (string, bool) {
	value := os.Getenv(demoUserEnv)
	if !orcidIDPattern.MatchString(value) {
		return "", false
	}
	return value, true
}

// mustDemoUserORCID is lookupDemoUserORCID for boot: it panics, naming the setting, when
// the value is unusable.
func mustDemoUserORCID() string {
	value, ok := lookupDemoUserORCID()
	if !ok {
		panic(demoUserEnv + " is required and has no default; set it to the ORCID iD of the seeded non-admin demo user that /auth/unauth_demo mints tokens for")
	}
	return value
}

// HandleDemoUser returns an HTTP handler that issues a JWT for the non-admin demo_user.
// Compiled in only under the `curatoriumdemo` build tag. Reachable only in-cluster on
// Curatorium's own deployment: the path is absent from the Traefik public route list
// and from the Next.js rewrite array; the browser reaches it through the frontend
// proxy /api/demo/unauth-token, which rate-limits it.
// This enables the demo/blast-live page to submit real BLAST jobs without ORCID login.
func HandleDemoUser(kvStore KeyValueStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		demoORCID, ok := lookupDemoUserORCID()
		if !ok {
			http.Error(w, "Demo user not configured", http.StatusInternalServerError)
			return
		}
		keyID, privKey, err := GetOrCreateSigningKey(kvStore)
		if err != nil {
			http.Error(w, "Failed to get signing key", http.StatusInternalServerError)
			return
		}
		jwtToken, err := signJWT(demoORCID, []string{"demo"}, privKey, keyID)
		if err != nil {
			http.Error(w, "Failed to sign JWT", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		cors(w, r)
		fmt.Fprintf(w, `{"jwt":%q}`, jwtToken)
	}
}
