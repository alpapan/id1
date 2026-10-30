package id1

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestOrcidCallbackRefusesReservedOrcidBlock drives the real ORCID callback with
// a token response naming each iD and checks that an iD in the reserved
// 0000-0000- block is refused before any token or login code is issued, while
// an iD outside the block still signs in through the same harness.
func TestOrcidCallbackRefusesReservedOrcidBlock(t *testing.T) {
	cases := []struct {
		name       string
		orcid      string
		wantStatus int
	}{
		{"admin account", "0000-0000-0000-0001", http.StatusForbidden},
		{"files account", "0000-0000-0000-0002", http.StatusForbidden},
		{"provisioner account", "0000-0000-0000-0009", http.StatusForbidden},
		{"test range above the system accounts", "0000-0000-0000-0108", http.StatusForbidden},
		{"block iD with an invalid check digit", "0000-0000-0000-0000", http.StatusForbidden},
		{"iD outside the block", "0000-0002-1825-0097", http.StatusFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"access_token":"test-access-token","token_type":"bearer","orcid":%q,"scope":"/authenticate"}`, tc.orcid)
			}))
			defer tokenServer.Close()

			h := newTestOrcidHandlerWithState(t, tokenServer.URL, getFrontendURL(), map[string]stateEntry{
				"reserved_state": {created: time.Now(), verifier: "test_verifier_12345"},
			})
			h.kvStore = ID1KeyValueStore{}

			req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=reserved_state&code=test_code", nil)
			rec := httptest.NewRecorder()
			h.HandleCallback(rec, withBinding(req))

			if rec.Code != tc.wantStatus {
				t.Fatalf("orcid %s: expected %d, got %d: %s", tc.orcid, tc.wantStatus, rec.Code, rec.Body.String())
			}
			if tc.wantStatus == http.StatusForbidden {
				if loc := rec.Header().Get("Location"); loc != "" {
					t.Errorf("orcid %s: refused callback still redirected to %q", tc.orcid, loc)
				}
				if _, set := rec.Header()["Set-Cookie"]; set {
					t.Errorf("orcid %s: refused callback re-issued the binding cookie", tc.orcid)
				}
			}
		})
	}
}
