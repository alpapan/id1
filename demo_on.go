//go:build curatoriumdemo

package id1

import (
	"fmt"
	"net/http"
)

// RegisterDemoRoutes registers the demo-identity mint at /auth/unauth_demo.
// Compiled in only under the `curatoriumdemo` build tag - Curatorium's own
// deployment, where four demo pages depend on it as production surface,
// reached only through the frontend's rate-limited in-cluster proxy
// /api/demo/unauth-token, never directly. Unconditional here: no ENV check,
// because those pages are live in every Curatorium environment including
// production. annot8r_id1 must never carry this handler - see demo_off.go.
func RegisterDemoRoutes(mux *http.ServeMux, kvStore KeyValueStore) {
	mux.HandleFunc("/auth/unauth_demo", HandleDemoUser(kvStore))
}

// demoUserORCID is the ORCID of the seeded demo_user (migrations/02b_user_core_seed.sql),
// granted all roles EXCEPT admin (migrations/99_seed_tables.sql). This is deliberately
// the NON-admin demo identity: the earlier value 0009-0002-8023-3658 is the real admin
// ORCID (all roles including admin), so minting it here from a public endpoint handed
// anonymous callers an admin token.
const demoUserORCID = "0009-0009-9355-3782"

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
		keyID, privKey, err := GetOrCreateSigningKey(kvStore)
		if err != nil {
			http.Error(w, "Failed to get signing key", http.StatusInternalServerError)
			return
		}
		jwtToken, err := signJWT(demoUserORCID, []string{"demo"}, privKey, keyID)
		if err != nil {
			http.Error(w, "Failed to sign JWT", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		cors(&w)
		fmt.Fprintf(w, `{"jwt":%q}`, jwtToken)
	}
}
