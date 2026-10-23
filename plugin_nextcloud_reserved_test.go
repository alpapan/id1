package id1

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refusedInternalOrcids are the internal accounts (admin, shared-folder,
// provisioner) that /internal/nc-provision and /internal/nc-token never serve.
var refusedInternalOrcids = []string{
	"0000-0000-0000-0001",
	"0000-0000-0000-0002",
	"0000-0000-0000-0009",
}

// allowedNearbyOrcids sit beside the refused ones: the seeded role users 0003-0008
// and the first iD past the reserved block.
var allowedNearbyOrcids = []string{
	"0000-0000-0000-0003",
	"0000-0000-0000-0004",
	"0000-0000-0000-0005",
	"0000-0000-0000-0006",
	"0000-0000-0000-0007",
	"0000-0000-0000-0008",
	"0000-0000-0000-0010",
}

type ncEndpointCase struct {
	name      string
	method    string
	path      string
	wantAllow int
	wantType  string
	wantBody  string
	build     func(ncURL string) http.HandlerFunc
}

func ncEndpointCases() []ncEndpointCase {
	return []ncEndpointCase{
		{
			name: "provision", method: "POST", path: "/internal/nc-provision", wantAllow: http.StatusNoContent,
			wantType: "text/plain; charset=utf-8", wantBody: "orcid not served\n",
			build: func(ncURL string) http.HandlerFunc {
				return HandleNcProvision(&NextcloudClient{URL: ncURL, Username: ncProvisionerTestUser, Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)
			},
		},
		{
			name: "token", method: "GET", path: "/internal/nc-token", wantAllow: http.StatusOK,
			wantType: "application/json", wantBody: `{"error":"orcid_not_served"}`,
			build: func(ncURL string) http.HandlerFunc {
				return HandleNcToken(&NextcloudClient{URL: ncURL, Username: ncProvisionerTestUser, Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)
			},
		},
	}
}

// A holder of the internal secret must not be able to create an account or mint
// an app password for an internal account: nothing reaches Nextcloud.
func TestNcEndpoints_RefuseInternalOrcids(t *testing.T) {
	for _, ep := range ncEndpointCases() {
		for _, orcid := range refusedInternalOrcids {
			t.Run(ep.name+"/"+orcid, func(t *testing.T) {
				ncURL, userCalls, mintCalls, cleanup := countingNextcloud(t, "SHOULD-NOT-BE-MINTED")
				defer cleanup()

				req := httptest.NewRequest(ep.method, ep.path+"?orcid="+orcid, nil)
				req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
				rr := httptest.NewRecorder()
				ep.build(ncURL).ServeHTTP(rr, req)

				require.Equal(t, http.StatusForbidden, rr.Code)
				assert.Equal(t, ep.wantType, rr.Header().Get("Content-Type"), "the refusal matches the sibling refusals of its handler")
				assert.Equal(t, ep.wantBody, rr.Body.String())
				assert.Equal(t, int32(0), atomic.LoadInt32(userCalls), "a refused iD must never reach Nextcloud")
				assert.Equal(t, int32(0), atomic.LoadInt32(mintCalls), "a refused iD must never be minted")
			})
		}
	}
}

// The refusal covers exactly the three internal accounts.
func TestNcEndpoints_ServeNearbyOrcids(t *testing.T) {
	for _, ep := range ncEndpointCases() {
		for _, orcid := range allowedNearbyOrcids {
			t.Run(ep.name+"/"+orcid, func(t *testing.T) {
				ncURL, _, _, cleanup := countingNextcloud(t, "TOKEN")
				defer cleanup()

				req := httptest.NewRequest(ep.method, ep.path+"?orcid="+orcid, nil)
				req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
				rr := httptest.NewRecorder()
				ep.build(ncURL).ServeHTTP(rr, req)

				assert.Equal(t, ep.wantAllow, rr.Code)
			})
		}
	}
}
