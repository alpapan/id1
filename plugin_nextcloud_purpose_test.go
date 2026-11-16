// apps/id1/plugin_nextcloud_purpose_test.go
//
// group: config
// tags: nextcloud, testing, credentials
// summary: Tests for the purpose parameter of /internal/nc-token, which selects the User-Agent Nextcloud names a new app password after.
//
//

package id1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const purposeTestOrcid = "0000-0000-0000-0108"

// purposeNextcloud is a fake Nextcloud (the external boundary) that records
// how many account-existence reads it served and the User-Agent of every
// getapppassword request. When acceptPassword is not empty, a mint is refused
// with HTTP 401 unless the request's Basic Auth password equals it. The test
// server is closed by t.Cleanup, so nothing outlives the test.
type purposeNextcloud struct {
	URL string

	mu             sync.Mutex
	lookups        int
	mintUserAgents []string
}

func newPurposeNextcloud(t *testing.T, acceptPassword string) *purposeNextcloud {
	t.Helper()
	fake := &purposeNextcloud{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, ncUserLookupPrefix):
			fake.lookups++
			fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"id":"0000-0000-0000-0108","enabled":true}}}`)
		case r.URL.Path == "/ocs/v2.php/core/getapppassword":
			fake.mintUserAgents = append(fake.mintUserAgents, r.Header.Get("User-Agent"))
			_, password, _ := r.BasicAuth()
			if acceptPassword != "" && password != acceptPassword {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"MINTED-TOKEN"}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	fake.URL = srv.URL
	return fake
}

// snapshot returns the existence-read count and a copy of the recorded
// User-Agents. Call it after the request under test has returned.
func (f *purposeNextcloud) snapshot() (lookups int, userAgents []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lookups, append([]string(nil), f.mintUserAgents...)
}

// callNcToken runs one GET /internal/nc-token request against a fresh handler
// (so no password block carries over between calls) and returns the recorder.
func callNcToken(t *testing.T, fake *purposeNextcloud, currentKey []byte, rawQuery string, previousKeys ...[]byte) *httptest.ResponseRecorder {
	t.Helper()
	handler := HandleNcToken(&NextcloudClient{URL: fake.URL, Username: ncProvisionerTestUser, Password: "secret"}, currentKey, "internal-secret", 2*time.Second, previousKeys...)
	req := httptest.NewRequest("GET", "/internal/nc-token?"+rawQuery, nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// The resolver turns the raw query string into the User-Agent, or refuses it. Every
// expected value is a hand-written literal, not computed by the code under test.
func TestNcMintUserAgentFor(t *testing.T) {
	cases := []struct {
		name      string
		query     string
		wantAgent string
		wantErr   error
	}{
		{name: "absent_purpose_is_interactive", query: "", wantAgent: "curatorium-auth/1"},
		{name: "explicit_interactive", query: "purpose=interactive", wantAgent: "curatorium-auth/1"},
		{name: "malformed_percent_escape", query: "purpose=%zz", wantErr: errNcInvalidQuery},
		{name: "semicolon_separator", query: "purpose=job&operation_id=5;x=1", wantErr: errNcInvalidQuery},
		{name: "empty_purpose", query: "purpose=", wantErr: errNcInvalidPurpose},
		{name: "unknown_purpose", query: "purpose=admin", wantErr: errNcInvalidPurpose},
		{name: "wrong_case_purpose", query: "purpose=JOB&operation_id=5", wantErr: errNcInvalidPurpose},
		{name: "repeated_purpose", query: "purpose=job&purpose=interactive&operation_id=5", wantErr: errNcInvalidPurpose},
		{name: "unknown_purpose_with_operation", query: "purpose=other&operation_id=5", wantErr: errNcInvalidPurpose},
		{name: "retired_job_purpose", query: "purpose=job&operation_id=5", wantErr: errNcInvalidPurpose},
		{name: "retired_job_purpose_without_operation", query: "purpose=job", wantErr: errNcInvalidPurpose},
		{name: "interactive_with_operation", query: "purpose=interactive&operation_id=5", wantErr: errNcInvalidOperationID},
		{name: "absent_purpose_with_operation", query: "operation_id=5", wantErr: errNcInvalidOperationID},
		{name: "device_with_name", query: "purpose=device&name=Alexs-Laptop", wantAgent: "curatorium-device/1 Alexs-Laptop"},
		{name: "device_name_with_dot_dash_underscore", query: "purpose=device&name=mirall_35.0.2-x86", wantAgent: "curatorium-device/1 mirall_35.0.2-x86"},
		{name: "device_name_at_the_length_cap", query: "purpose=device&name=" + strings.Repeat("a", 64), wantAgent: "curatorium-device/1 " + strings.Repeat("a", 64)},
		{name: "device_without_name", query: "purpose=device", wantErr: errNcInvalidDeviceName},
		{name: "device_empty_name", query: "purpose=device&name=", wantErr: errNcInvalidDeviceName},
		{name: "device_name_over_the_length_cap", query: "purpose=device&name=" + strings.Repeat("a", 65), wantErr: errNcInvalidDeviceName},
		{name: "device_name_with_a_space", query: "purpose=device&name=Alexs%20Laptop", wantErr: errNcInvalidDeviceName},
		{name: "device_name_with_a_slash", query: "purpose=device&name=a%2Fb", wantErr: errNcInvalidDeviceName},
		{name: "device_name_header_injection", query: "purpose=device&name=a%0d%0aX-Evil%3A%201", wantErr: errNcInvalidDeviceName},
		{name: "device_repeated_name", query: "purpose=device&name=a&name=b", wantErr: errNcInvalidDeviceName},
		{name: "device_with_operation", query: "purpose=device&name=a&operation_id=5", wantErr: errNcInvalidOperationID},
		{name: "interactive_with_name", query: "purpose=interactive&name=a", wantErr: errNcInvalidDeviceName},
		{name: "absent_purpose_with_name", query: "name=a", wantErr: errNcInvalidDeviceName},
		{name: "wrong_case_device", query: "purpose=DEVICE&name=a", wantErr: errNcInvalidPurpose},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent, err := ncMintUserAgentFor(tc.query)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Empty(t, agent, "a refused request must yield no User-Agent")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantAgent, agent)
		})
	}
}

// The User-Agent chosen by the purpose is the one Nextcloud receives on the
// getapppassword request, which is what Nextcloud names the token after.
func TestHandleNcTokenPurpose_ChoosesTheUserAgentNextcloudNamesTheTokenAfter(t *testing.T) {
	cases := []struct {
		name      string
		query     string
		wantAgent string
	}{
		{name: "no_purpose_is_interactive", query: "", wantAgent: "curatorium-auth/1"},
		{name: "interactive", query: "&purpose=interactive", wantAgent: "curatorium-auth/1"},
		{name: "device", query: "&purpose=device&name=Alexs-Laptop", wantAgent: "curatorium-device/1 Alexs-Laptop"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newPurposeNextcloud(t, "")

			rr := callNcToken(t, fake, []byte("test-key"), "orcid="+purposeTestOrcid+tc.query)

			require.Equal(t, http.StatusOK, rr.Code)
			var body map[string]string
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, "MINTED-TOKEN", body["token"])
			lookups, agents := fake.snapshot()
			assert.Equal(t, 1, lookups)
			assert.Equal(t, []string{tc.wantAgent}, agents)
		})
	}
}

// A bad purpose or operation_id is answered 400 before id1 asks Nextcloud
// anything: no existence read and, above all, no mint.
func TestHandleNcTokenPurpose_RejectsABadRequestBeforeAnyNextcloudCall(t *testing.T) {
	cases := []struct {
		name     string
		query    string
		wantCode string
	}{
		{name: "malformed_pair_is_not_dropped", query: "&purpose=job;x=1", wantCode: "invalid_query"},
		{name: "unknown_purpose", query: "&purpose=admin", wantCode: "invalid_purpose"},
		{name: "empty_purpose", query: "&purpose=", wantCode: "invalid_purpose"},
		{name: "retired_job_purpose", query: "&purpose=job&operation_id=5", wantCode: "invalid_purpose"},
		{name: "operation_id_without_purpose", query: "&operation_id=5", wantCode: "invalid_operation_id"},
		{name: "device_without_name", query: "&purpose=device", wantCode: "invalid_device_name"},
		{name: "device_name_with_a_space", query: "&purpose=device&name=a%20b", wantCode: "invalid_device_name"},
		{name: "device_with_operation_id", query: "&purpose=device&name=a&operation_id=5", wantCode: "invalid_operation_id"},
		{name: "name_without_purpose", query: "&name=a", wantCode: "invalid_device_name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newPurposeNextcloud(t, "")

			rr := callNcToken(t, fake, []byte("test-key"), "orcid="+purposeTestOrcid+tc.query)

			require.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
			var body map[string]string
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, tc.wantCode, body["error"])
			lookups, agents := fake.snapshot()
			assert.Equal(t, 0, lookups, "a refused request must not reach Nextcloud")
			assert.Empty(t, agents, "a refused request must mint nothing")
		})
	}
}

// MintAppToken sends the User-Agent it is given and refuses to send none: an
// empty header would let Nextcloud name the token after an empty string, which
// no revocation predicate could tell from any other unnamed token.
func TestNextcloudClient_MintAppToken_RefusesAnEmptyUserAgent(t *testing.T) {
	fake := newPurposeNextcloud(t, "")

	c := &NextcloudClient{URL: fake.URL}
	_, err := c.MintAppToken(context.Background(), purposeTestOrcid, "NC_pw", "")

	require.Error(t, err)
	_, agents := fake.snapshot()
	assert.Empty(t, agents, "no request may be sent with an empty User-Agent")
}
