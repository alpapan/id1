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

const purposeTestOrcid = "0009-0002-8023-3658"

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
			fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"id":"0009-0002-8023-3658","enabled":true}}}`)
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
	handler := HandleNcToken(&NextcloudClient{URL: fake.URL, Username: "admin", Password: "secret"}, currentKey, "internal-secret", 2*time.Second, previousKeys...)
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
		{name: "job_with_operation", query: "purpose=job&operation_id=1234", wantAgent: "curatorium-job/1 op=1234"},
		{name: "job_max_int64", query: "purpose=job&operation_id=9223372036854775807", wantAgent: "curatorium-job/1 op=9223372036854775807"},
		{name: "job_plus_sign_is_built_from_the_parsed_integer", query: "purpose=job&operation_id=%2B5", wantAgent: "curatorium-job/1 op=5"},
		{name: "job_leading_zeros_are_built_from_the_parsed_integer", query: "purpose=job&operation_id=007", wantAgent: "curatorium-job/1 op=7"},
		{name: "malformed_percent_escape", query: "purpose=%zz", wantErr: errNcInvalidQuery},
		{name: "semicolon_separator", query: "purpose=job&operation_id=5;x=1", wantErr: errNcInvalidQuery},
		{name: "empty_purpose", query: "purpose=", wantErr: errNcInvalidPurpose},
		{name: "unknown_purpose", query: "purpose=admin", wantErr: errNcInvalidPurpose},
		{name: "wrong_case_purpose", query: "purpose=JOB&operation_id=5", wantErr: errNcInvalidPurpose},
		{name: "repeated_purpose", query: "purpose=job&purpose=interactive&operation_id=5", wantErr: errNcInvalidPurpose},
		{name: "unknown_purpose_with_operation", query: "purpose=other&operation_id=5", wantErr: errNcInvalidPurpose},
		{name: "job_without_operation", query: "purpose=job", wantErr: errNcInvalidOperationID},
		{name: "job_empty_operation", query: "purpose=job&operation_id=", wantErr: errNcInvalidOperationID},
		{name: "job_zero_operation", query: "purpose=job&operation_id=0", wantErr: errNcInvalidOperationID},
		{name: "job_negative_operation", query: "purpose=job&operation_id=-3", wantErr: errNcInvalidOperationID},
		{name: "job_overflowing_operation", query: "purpose=job&operation_id=9223372036854775808", wantErr: errNcInvalidOperationID},
		{name: "job_letters_after_digits", query: "purpose=job&operation_id=12abc", wantErr: errNcInvalidOperationID},
		{name: "job_leading_space", query: "purpose=job&operation_id=%205", wantErr: errNcInvalidOperationID},
		{name: "job_decimal", query: "purpose=job&operation_id=1.5", wantErr: errNcInvalidOperationID},
		{name: "job_hex", query: "purpose=job&operation_id=0x10", wantErr: errNcInvalidOperationID},
		{name: "job_header_injection", query: "purpose=job&operation_id=5%0d%0aX-Evil%3A%201", wantErr: errNcInvalidOperationID},
		{name: "job_repeated_operation", query: "purpose=job&operation_id=1&operation_id=2", wantErr: errNcInvalidOperationID},
		{name: "interactive_with_operation", query: "purpose=interactive&operation_id=5", wantErr: errNcInvalidOperationID},
		{name: "absent_purpose_with_operation", query: "operation_id=5", wantErr: errNcInvalidOperationID},
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
		{name: "job", query: "&purpose=job&operation_id=1234", wantAgent: "curatorium-job/1 op=1234"},
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
		{name: "job_without_operation_id", query: "&purpose=job", wantCode: "invalid_operation_id"},
		{name: "job_zero_operation_id", query: "&purpose=job&operation_id=0", wantCode: "invalid_operation_id"},
		{name: "job_non_numeric_operation_id", query: "&purpose=job&operation_id=abc", wantCode: "invalid_operation_id"},
		{name: "operation_id_without_purpose", query: "&operation_id=5", wantCode: "invalid_operation_id"},
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

// During a derivation-key rotation the handler tries the current key, then the
// previous one. Every attempt is a separate getapppassword request, and every
// one must carry the job's User-Agent, or the token that finally succeeds
// could be named for the wrong purpose.
func TestHandleNcTokenPurpose_JobUserAgentIsSentOnEveryDerivationKeyAttempt(t *testing.T) {
	currentKey := []byte("current-derivation-key")
	previousKey := []byte("previous-derivation-key")
	previousPassword, err := DeriveNextcloudPassword(previousKey, purposeTestOrcid)
	require.NoError(t, err)
	fake := newPurposeNextcloud(t, previousPassword)

	rr := callNcToken(t, fake, currentKey, "orcid="+purposeTestOrcid+"&purpose=job&operation_id=77", previousKey)

	require.Equal(t, http.StatusOK, rr.Code)
	_, agents := fake.snapshot()
	assert.Equal(t, []string{"curatorium-job/1 op=77", "curatorium-job/1 op=77"}, agents)
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
